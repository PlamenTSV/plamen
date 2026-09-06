# Phase 5: Verification Prompt Template - Solana

> **Usage**: Orchestrator reads this file and spawns verification agents for Solana program audits.
> Replace placeholders `{SCRATCHPAD}`, `{HYPOTHESIS_ID}`, `{LOCATION}`, etc. with actual values.

---

## Verification Order

1. ALL chain hypotheses (regardless of original severity)
2. HIGH/CRITICAL standalone hypotheses
3. **ALL MEDIUM standalone hypotheses (MANDATORY)**

> Empirical testing showed 44% false positive rate on unverified Mediums. Medium verification is mandatory for report precision.

## Model Selection

| Verification Target | Model | Rationale |
|---------------------|-------|-----------|
| Chain hypotheses | opus | Complex multi-step attack sequences need deep reasoning |
| HIGH/CRITICAL standalone | opus | Highest-impact findings need highest-quality verification |
| **MEDIUM standalone** | **sonnet** | PoC generation for Medium findings is pattern-matching (code trace + boundary check), not deep architectural reasoning. Sonnet handles this well at lower cost. |

The orchestrator passes the model parameter when spawning security-verifier agents. All verifiers use the same prompt template below regardless of model.

## Verifier Agent

```
Task(subagent_type="security-verifier", prompt="
Verify hypothesis: {HYPOTHESIS_ID}

Location: {LOCATION}
Claim: {IF/THEN/BECAUSE statement}

Read:
- {SCRATCHPAD}/design_context.md
- ~/.claude/agents/skills/solana/verification-protocol/SKILL.md
- ~/.claude/rules/phase5-poc-execution.md

## PRECISION MODE
You are in PRECISION mode. Your job is to VALIDATE or REFUTE hypotheses with maximum rigor. Unlike discovery agents who err on the side of reporting, you err on the side of ACCURACY. Every claim must be backed by exact line numbers, concrete state values, and verifiable code traces. If you cannot prove exploitation with specific values, say so clearly. A false positive (confirming a non-bug) wastes remediation effort and undermines audit credibility.

## DUAL-PERSPECTIVE VERIFICATION (MANDATORY)

Phase 1 - ATTACKER: Assume you ARE the attacker.
- What's your complete attack sequence (which instructions, in what order)?
- What's the profit/damage with real numbers?
- Why would this succeed?

Phase 2 - DEFENDER: Assume you're the protocol team.
- What mechanism prevents this?
- What assumption is wrong?
- Why is this safe by design?

Phase 3 - VERDICT: Which argument won?

## ANTI-DOWNGRADE GUARD (MANDATORY for VS/BLIND findings)

When verifying a finding originally from the Validation Sweep ([VS-*]) or Blind Spot Scanner
([BLIND-*]), you MUST apply Rule 13's 5-question test BEFORE downgrading severity or
marking FALSE_POSITIVE:

1. **Who is harmed** by this design gap?
2. **Can affected users avoid** the harm?
3. **Is the gap documented** in protocol docs?
4. **Could the protocol achieve the same goal** without this gap?
5. **Does the instruction fulfill its stated purpose completely?**

**HARD RULE**: If the finding shows Instruction A has protection X but Instruction B lacks it for
the same user action → this is a defense parity gap, NOT "by design". Minimum severity: Medium.

You may NOT dismiss a defense parity gap as "Informational" or "design note".

## CLASS-CHECK BEFORE FALSE_POSITIVE

Before marking ANY finding FALSE_POSITIVE, check: does the same code location have other exploitable instances of the same vulnerability CLASS? If the specific scenario is unreachable but a variant at the same location is valid, downgrade the original scenario but report the valid variant.

## MANDATORY PoC EXECUTION

Follow `phase5-poc-execution.md`. Compile and run every PoC - a written test with no execution output is not evidence.

**Solana commands**: `cargo build-sbf` or `anchor build` (compile), `cargo test test_{hypothesis_id} -- --nocapture` (run). For fuzz variants: check `build_status.md` for `trident_available`. If true (Anchor project): use Trident v0.11+ (`cd trident-tests && trident fuzz run fuzz_0` - no honggfuzz needed). If false: use proptest with bounded inputs or boundary-value parameterized tests. See `phase5-poc-execution.md` for templates and Trident commands.

### PoC File Placement (MANDATORY — in-crate authoring)

Author the PoC as a **NEW in-crate file** `src/poc_{hypothesis_id}.rs` inside
the target workspace member, wired in via `#[cfg(test)] mod poc_{hypothesis_id};`
added to that member's `lib.rs`. Record in the PoC Attempt Ledger:
- **Test File**: `<crate>/src/poc_{hypothesis_id}.rs`
- **Command**: `cargo test -p <crate> test_{hypothesis_id} -- --nocapture`

**FORBIDDEN shapes** (do not use as the PoC's primary authoring location):
- Writing the test body directly inline into `lib.rs` — a `Test File: lib.rs`
  entry is an excluded basename and is not a valid PoC location.
- A bare top-level `tests/*.rs` integration test as the PRIMARY PoC shape.

**Why (generic — no protocol/crate names)**: a crate declaring only
`crate-type = ["cdylib"]` has no `rlib` target, so a `tests/*.rs` integration
test — which links against the crate as an external dependency — can fail to
link (an E0463-class "can't find crate" error) because there is no rlib to
link against. An in-crate `#[cfg(test)] mod` compiles as part of the crate's
own `rustc --test` compilation unit, so it builds and runs regardless of
`crate-type`. This is a structural build-shape fact, not a per-project
exception, so the in-crate mandate applies uniformly.

**Solana carve-out — no `--features testutils`**: unlike Soroban, Solana
program crates typically declare a default `lib` target alongside `cdylib`,
which emits an `rlib` — so a `tests/*.rs` integration test would usually
link fine here. The in-crate mandate above still applies uniformly for
authoring consistency, but the Command MUST NOT include `--features testutils`
(that flag is Soroban-SDK-specific and does not exist on Solana's build).

### PoC Attempt Ledger (MANDATORY)

Every verifier output for this finding MUST include this ledger BEFORE
the evidence tag is finalized. Source-of-truth schema:
`rules/phase5-poc-execution.md` § "PoC Testability Ledger".

```markdown
### PoC Attempt
- PoC Required: YES/NO
- PoC Class: <unit|property|integration|structural>
- Attempted: YES/NO
- PoC Not Attempted Because: <NO_BUILD_ENVIRONMENT|EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS|DEPLOYMENT_ONLY_REQUIRES_LIVE_EXTERNAL|PURE_SPEC_OR_DOCS_ONLY|STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION|CROSS_VM_ENCODING_NO_RUNTIME|N/A>
- Test File: <path or N/A>
- Command: <command or N/A>
```

`unit` and `property` rows require a real executable attempt when a
build/test harness exists. "no test written" with `[CODE-TRACE]`
fallback is INVALID unless the ledger names an environmental blocker
from the allowed-reasons list. `STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION`
is not an allowed skip reason for `unit` or `property` — reclassify
the row or attempt the test.

### Force-by-Default Skip Justification (MANDATORY)

`STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION` is NOT a valid skip for a finding
with a concrete Material Harm (fund/state/privilege/liveness/accounting
delta). The default is to FORCE the PoC. A skip requires citing a SPECIFIC
blocker from the closed taxonomy in `~/.claude/rules/phase5-poc-execution.md`
§ "Force-by-Default Skip Justification" — `FULLY_TRUSTED_DESIGN`,
`DEPLOY_OR_TX_ORDERING`, `EXTERNAL_DEP_NO_FORK`, `LIVE_ARTIFACT_REQUIRED`,
`SPEC_DOCS_NO_STATE_DELTA`, or a `REFUTED` verdict — with a code-grounded
justification (name the trusted actor, the initializer, the external call,
the artifact, or the absent state delta). A forced attempt that genuinely
cannot assert the harm records `[CODE-TRACE]` plus the named blocker, NOT
`[POC-FAIL]` — `[POC-FAIL]` is reserved for a harm-asserting test that ran
and the harm did not reproduce.

## ANTI-HALLUCINATION RULES

1. You MUST read the actual source files BEFORE writing any test or analysis. Do NOT guess function signatures, parameter types, or return values.
2. You MUST extract real constants from the program (decimals, fee rates, bounds, period lengths) and use those in your test. Never invent convenient values.
3. If an instruction handler signature differs from what you expected, use the ACTUAL signature from the source code.
4. When tracing code logic, verify the DIRECTION of comparisons (>=, <=, >, <). A >= in an error condition has the opposite meaning from >= in a success condition.
5. Before claiming a state field is "not updated" by an instruction, grep for ALL writes to that field across the entire codebase. The instruction may update it indirectly via a CPI or helper.
6. If you cannot compile or run a test after 5 attempts, provide a MANUAL CODE TRACE with exact line numbers and concrete state transitions. Tag as `[CODE-TRACE]` and set verdict to CONTESTED (not CONFIRMED). A code trace with real values is better than a hallucinated test, but it is NOT mechanical proof.

## REALISTIC PARAMETER VALIDATION
Substitute ACTUAL program constants (basis points, fees, thresholds, CU limits).
Apply Rule 10: Use worst realistic operational state, not current snapshot.
State: 'With real constants [values] at worst-state [params], bug triggers when [condition]'
OR: 'With real constants [values] at worst-state [params], bug does NOT trigger because [reason]'

## PROTOCOL-LEVEL CONTEXT
Consider:
- TVL at risk: what's the maximum extractable value?
- Repeatability: once or continuous?
- User population: one user or all users?
- CU constraints: does the attack fit within transaction limits?

## SOLANA-SPECIFIC PoC FRAMEWORK: LiteSVM (Rust)

### Basic PoC Structure

```rust
use litesvm::LiteSVM;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::Transaction,
    system_program,
};

#[test]
fn test_exploit() {
    let mut svm = LiteSVM::new();

    // 1. DEPLOY: Load program
    let program_id = Pubkey::new_unique();
    let program_bytes = include_bytes!("../../target/deploy/program.so");
    svm.add_program(program_id, program_bytes);

    // 2. SETUP: Create accounts, fund wallets
    let attacker = Keypair::new();
    let victim = Keypair::new();
    svm.airdrop(&attacker.pubkey(), 10_000_000_000).unwrap(); // 10 SOL
    svm.airdrop(&victim.pubkey(), 10_000_000_000).unwrap();

    // 3. SETUP: Create PDAs, token mints, token accounts
    let (pda, bump) = Pubkey::find_program_address(
        &[b"vault", attacker.pubkey().as_ref()],
        &program_id,
    );
    // ... create_mint, create_associated_token_account, etc.

    // 4. SETUP: Normal protocol operations (deposits, etc.)
    // ... execute setup instructions

    // 5. RECORD BEFORE
    let balance_before = svm.get_balance(&victim.pubkey()).unwrap();

    // 6. ATTACK: Execute exploit instruction(s)
    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(attacker.pubkey(), true),      // signer
            AccountMeta::new(pda, false),                    // PDA
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: exploit_data.try_to_vec().unwrap(),
    };
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&attacker.pubkey()),
        &[&attacker],
        svm.latest_blockhash(),
    );
    let result = svm.send_transaction(tx);

    // 7. VERIFY: Assert impact
    match result {
        Ok(_) => {
            let balance_after = svm.get_balance(&victim.pubkey()).unwrap();
            assert!(balance_after < balance_before, "Victim lost funds");
        }
        Err(e) => {
            // Document WHY the exploit was prevented
            panic!("Attack reverted: {:?}", e);
        }
    }
}
```

### Account Substitution Attack PoC

```rust
use solana_sdk::account::AccountSharedData;

#[test]
fn test_account_substitution() {
    let mut svm = LiteSVM::new();

    // Create fake account with arbitrary data
    let fake_pubkey = Pubkey::new_unique();
    let mut fake_data = vec![0u8; expected_data_len];
    // Write malicious data into account
    fake_data[0..8].copy_from_slice(&malicious_discriminator);

    let fake_account = AccountSharedData::new_data(
        rent_exempt_lamports,
        &fake_data,
        &fake_owner, // attacker-controlled owner
    ).unwrap();
    svm.set_account(fake_pubkey, fake_account);

    // Pass fake account to instruction
    // ...
}
```

### CPI Attack PoC

```rust
#[test]
fn test_cpi_attack() {
    let mut svm = LiteSVM::new();

    // Deploy target program
    let target_id = Pubkey::new_unique();
    svm.add_program(target_id, include_bytes!("target.so"));

    // Deploy malicious program that mimics target interface
    let malicious_id = Pubkey::new_unique();
    svm.add_program(malicious_id, include_bytes!("malicious.so"));

    // If program_id is user-supplied: pass malicious_id instead of target_id
    // ...
}
```

### Multi-Instruction Transaction PoC (Instruction Composition Attack)

```rust
#[test]
fn test_instruction_composition() {
    let mut svm = LiteSVM::new();

    // Build transaction with multiple instructions
    let ix1 = /* manipulate state */;
    let ix2 = /* exploit manipulated state */;
    let ix3 = /* restore state (optional) */;

    let tx = Transaction::new_signed_with_payer(
        &[ix1, ix2, ix3], // All execute atomically
        Some(&attacker.pubkey()),
        &[&attacker],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).unwrap();
}
```

### Production Data Loading

Since there's no Anvil-equivalent for Solana:
1. Dump production accounts: `solana account --output json <address> > account.json`
2. Load into LiteSVM:
```rust
let account_data: serde_json::Value = serde_json::from_str(&json_str).unwrap();
let shared_data = AccountSharedData::new_data(
    lamports,
    &data_bytes,
    &owner_pubkey,
).unwrap();
svm.set_account(pubkey, shared_data);
```
3. Evidence tag: `[PROD-LITESVM]`

### Fork Testing Limitation
Document: No Anvil-equivalent fork testing for Solana. LiteSVM with manual account dumps is the closest alternative. For CONTESTED findings involving external program behavior, this limits evidence quality to `[PROD-LITESVM]` at best.

## ERROR TRACE OUTPUT
When verdict is CONTESTED or FALSE_POSITIVE, document:

### Error Trace
- **Failure Type**: INSTRUCTION_ERROR / CUSTOM_ERROR / INSUFFICIENT_FUNDS / ACCOUNT_NOT_FOUND / INSUFFICIENT_EVIDENCE
- **Location**: {program}:{instruction}:{handler function where failure occurs}
- **Error Code**: {custom error code or system error, if any}
- **State at Failure**: {key account data and values when the test failed}
- **Investigation Question**: {What specific question would need to be answered to resolve this}

## NEW OBSERVATIONS (MANDATORY)
If during verification you discover a NEW bug, configuration dependency, or edge case
NOT covered by any existing hypothesis - document it under:

### New Observations
- [VER-NEW-1]: {title} - {location} - {brief description}

These will be reviewed by the orchestrator for possible inclusion as new findings.

## INDEPENDENT SEVERITY ASSESSMENT (MANDATORY — M4 anti-inflation)

Before reconciling with any pre-assigned/claimed severity (from the hypothesis, queue, or inventory), assess a severity INDEPENDENTLY:

1. Read ONLY the code and your own evidence (PoC result, code trace, dual-perspective verdict from above). Deliberately IGNORE the claimed/pre-assigned severity for this step - do not let it anchor your judgment.
2. Apply the standard severity matrix (Impact x Likelihood) from `~/.claude/rules/report-template.md` to what YOU found, as if no severity had been pre-assigned.
3. Record the result in your output BEFORE finalizing your Severity field:

```
**Independent Severity**: <Critical|High|Medium|Low|Informational|N/A>
```

- Assessed from the code and evidence ALONE; ignore any pre-assigned severity.
- Use `N/A` ONLY when your verdict is REFUTED/FALSE_POSITIVE (no independent severity applies to a non-finding).
- This field is MANDATORY for every non-REFUTED verdict. The driver reads it to mechanically compute `final = min(Independent Severity, claimed severity)` - this can ONLY LOWER the reported severity, it NEVER raises it and NEVER drops the finding. A missing or unparseable field is recall-safe: it simply falls back to the claimed severity (no cap applied).

Do NOT skip this field to save time, and do NOT default it to the claimed severity - that defeats its purpose of catching an inflated pre-assigned severity.

## FIX GENERATION (POC-PASS only)
If your PoC PASSES (verdict = CONFIRMED with [POC-PASS]):
1. Write a minimal diff-style fix (smallest change that eliminates the bug)
2. If time permits, re-run the PoC with the fix applied to verify it no longer triggers
3. Include in your output under `### Suggested Fix` per phase5-poc-execution.md
4. If the fix is non-trivial (architectural, multi-file): write a 1-sentence description instead of a diff

Do NOT generate fixes for [CODE-TRACE] or [POC-FAIL] findings.

Write FULL PoC to {SCRATCHPAD}/verify_{hypothesis_id}.md
Include the mandatory `### Execution Result` and `### Fuzz Result` (Medium+) sections per phase5-poc-execution.md.

Return: CONFIRMED/FALSE_POSITIVE/CONTESTED + evidence tag + 3-sentence justification
")
```

**Escalation**: If 3+ agents flagged root cause AND verifier says FALSE_POSITIVE → override to CONTESTED.

---

## Independent Skeptic Challenge Boundary (Thorough mode)

> **Ownership:** This ecosystem verification prompt ends with the standard verifier. It MUST NOT spawn skeptic or judge workers, apply a skeptic proposal, or change report severity or disposition.
> **Triggering:** After standard verification, the driver constructs an independent semantic trigger manifest across all severities. Severity alone is neither an eligibility rule nor an exclusion rule.
> **Execution:** The shared driver-owned skeptic methodology receives that manifest and the applicable ecosystem anti-hallucination constraints. Its artifact is proposal-only and has no report authority. A distinct typed adjudicator receives each challenge requiring disposition; skeptic and adjudicator MUST NOT be the same worker or session.
> **Completeness:** A hash-bound receipt MUST account for every exact manifest finding ID once. Missing, duplicate, unknown, stale, or constituent-substituted IDs make the phase incomplete and require retry or explicit human-review degradation; they are never silently skipped.
> **Authority:** Only a validated, report-authoritative typed severity/disposition ledger can change upstream severity or disposition. Legacy `skeptic_*.md` and `judge_*.md` files are diagnostic or proposal artifacts only.
> **Recall floor:** `UNRESOLVED` and `PARTIAL` preserve the highest supported upstream tier and remain visible in the report body. They create explicit review work, never an automatic demotion or exclusion.

Execution details belong to the shared driver-owned skeptic and typed-adjudication contracts; do not copy them into an ecosystem verifier prompt.

---

## Cross-Batch Consistency Check (Phase 5.2)

> **Purpose**: When one verification batch marks a mechanism as FALSE_POSITIVE, other batches may still contain findings that depend on the same invalidated mechanism. Parallel batches cannot detect this — a post-batch reconciliation step is needed.
> **Trigger**: Always, after ALL verification batches complete (Phase 5 + 5.1). Runs before Phase 5.5 (finding extraction).
> **Model**: haiku (mechanical cross-reference)
> **Budget**: 1 agent (not counted against verification budget)

### Orchestrator spawns:

```
Task(subagent_type="general-purpose", model="haiku", prompt="
You are the Cross-Batch Consistency Agent.

## Your Task
Read ALL verification batch files: {SCRATCHPAD}/verify_batch_*.md

### STEP 1: Extract FALSE_POSITIVE mechanisms
For each FALSE_POSITIVE verdict, extract:
| Finding ID | Invalidated Mechanism | Reason | Batch Source |

### STEP 2: Cross-reference surviving findings
For each invalidated mechanism, search ALL other batch files for findings whose
attack path, precondition, or root cause depends on the same mechanism.

A finding DEPENDS on the mechanism if:
- It references the same function/code path that was proven non-exploitable
- Its attack requires the behavior the FALSE_POSITIVE disproved
- It is a chain hypothesis whose constituent was the FALSE_POSITIVE

### STEP 3: Flag contradictions
| Surviving Finding | Batch | Depends On | FALSE_POSITIVE ID | Contradiction |

### STEP 4: Recommend
For each contradiction:
- If the surviving finding's ENTIRE attack path depends on the disproved mechanism → recommend FALSE_POSITIVE
- If only part of the attack path is affected → recommend DOWNGRADE with explanation
- If the dependency is unclear → recommend REVIEW

Write to {SCRATCHPAD}/cross_batch_consistency.md
Return: 'DONE: {N} FALSE_POSITIVES checked, {C} contradictions found, {R} recommendations'
")
```

### Orchestrator action after agent returns:
- If contradictions found: apply recommendations (FALSE_POSITIVE or DOWNGRADE) before Phase 5.5
- If no contradictions: proceed to Phase 5.5
- Log results in {SCRATCHPAD}/verification_consistency.md
