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

## MANDATORY PoC EXECUTION (v9.9.5)

Follow `phase5-poc-execution.md`. Compile and run every PoC - a written test with no execution output is not evidence.

**Solana commands**: `cargo build-sbf` or `anchor build` (compile), `cargo test test_{hypothesis_id} -- --nocapture` (run). For fuzz variants: check `build_status.md` for `trident_available`. If true (Anchor project): use Trident v0.11+ (`cd trident-tests && trident fuzz run fuzz_0` - no honggfuzz needed). If false: use proptest with bounded inputs or boundary-value parameterized tests. See `phase5-poc-execution.md` for templates and Trident commands.

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

Write FULL PoC to {SCRATCHPAD}/verify_{hypothesis_id}.md
Include the mandatory `### Execution Result` and `### Fuzz Result` (Medium+) sections per phase5-poc-execution.md.

Return: CONFIRMED/FALSE_POSITIVE/CONTESTED + evidence tag + 3-sentence justification
")
```

**Escalation**: If 3+ agents flagged root cause AND verifier says FALSE_POSITIVE → override to CONTESTED.

---

## Skeptic-Judge Verification (Thorough mode only, HIGH/CRIT)

> **Purpose**: Challenge the standard verifier's reasoning. Nobody audits the auditor - this step does.
> **Trigger**: Thorough mode, findings with severity HIGH or CRITICAL, after standard Phase 5 verification completes.
> **Architecture**: Standard verifier → Skeptic agent (sonnet) → Judge agent (haiku, only if disagreement)

### Step 1: Spawn Skeptic Agent (per finding)

For each HIGH/CRIT finding after standard verification:

```
Task(subagent_type="security-verifier", model="sonnet", prompt="
You are the SKEPTIC VERIFIER. Your job is to challenge the standard verifier's conclusion.

## INVERSION MANDATE
The standard verifier concluded: {STANDARD_VERDICT} for hypothesis {HYPOTHESIS_ID}.
Your job is to argue the OPPOSITE:
- If standard said CONFIRMED → you MUST try to REFUTE. Find why this attack CANNOT work.
- If standard said FALSE_POSITIVE → you MUST try to CONFIRM. Find why this attack CAN work.
- If standard said CONTESTED → you MUST try to reach a definitive verdict (either direction).

## Your Inputs
Read:
- {SCRATCHPAD}/verify_{hypothesis_id}.md (standard verifier's full analysis)
- The source files at {LOCATION}
- {SCRATCHPAD}/design_context.md
- ~/.claude/rules/phase5-poc-execution.md

## HARD RULES
1. You MUST make your OWN tool calls. Do NOT rely on the standard verifier's code traces.
2. You MUST read the source code yourself. Do NOT trust the standard verifier's code quotes.
3. You MUST try to write and execute a PoC that proves the OPPOSITE of the standard verdict.
4. If the standard verifier's PoC passed, try to show why it doesn't prove what it claims (wrong setup, unrealistic parameters, missing preconditions).
5. If the standard verifier's PoC failed, try to show a variant that succeeds (different parameters, different entry point, different timing).

## Output
Write to {SCRATCHPAD}/skeptic_{hypothesis_id}.md:

### Skeptic Verdict
- **Standard Verdict**: {STANDARD_VERDICT}
- **Skeptic Verdict**: {CONFIRMED/FALSE_POSITIVE/CONTESTED}
- **Agreement**: {AGREE/DISAGREE}
- **Evidence Tag**: {[POC-PASS]/[POC-FAIL]/[CODE-TRACE]}
- **Reasoning**: {3-5 sentences explaining your position}

If DISAGREE: include your counter-PoC or counter-trace.

Return: '{AGREE/DISAGREE}: skeptic says {verdict} vs standard {STANDARD_VERDICT} - {1-line reason}'
")
```

### Step 2: Evaluate Agreement

After skeptic agent returns:
- If **AGREE** → final verdict = standard verdict (high confidence, both perspectives aligned)
- If **DISAGREE** → spawn Judge Agent (Step 3)

### Step 3: Spawn Judge Agent (only on disagreement)

```
Task(subagent_type="general-purpose", model="haiku", prompt="
You are the JUDGE. Two verifiers disagree on hypothesis {HYPOTHESIS_ID}. Your job is to determine which argument has STRONGER mechanical evidence.

## Prove It or Lose It
Read BOTH verification files:
- {SCRATCHPAD}/verify_{hypothesis_id}.md (standard verifier)
- {SCRATCHPAD}/skeptic_{hypothesis_id}.md (skeptic verifier)

## Decision Criteria (STRICTLY mechanical)
1. `[POC-PASS]` beats `[CODE-TRACE]` - always. Executed test > manual reasoning.
2. `[POC-PASS]` beats `[POC-FAIL]` - the test that passes wins.
3. If both have `[POC-PASS]` (conflicting tests) → verdict = CONTESTED
4. If both have `[CODE-TRACE]` only → whichever traces MORE concrete values with SPECIFIC line numbers wins. If roughly equal depth → CONTESTED.
5. If one has `[MEDUSA-PASS]` → that side wins (fuzzer counterexample is mechanical proof).

## Output
Write to {SCRATCHPAD}/judge_{hypothesis_id}.md:

### Judge Ruling
- **Standard Verdict**: {verdict} with {evidence_tag}
- **Skeptic Verdict**: {verdict} with {evidence_tag}
- **Ruling**: {STANDARD_WINS/SKEPTIC_WINS/CONTESTED}
- **Final Verdict**: {CONFIRMED/FALSE_POSITIVE/CONTESTED}
- **Reasoning**: {2-3 sentences - which evidence was mechanically stronger}

Return: 'RULING: {final_verdict} - {STANDARD_WINS/SKEPTIC_WINS/CONTESTED}'
")
```

### Step 4: Apply Final Verdict

| Outcome | Final Verdict | Confidence |
|---------|--------------|------------|
| Skeptic AGREES | Standard verdict | HIGH (dual-confirmed) |
| Judge: STANDARD_WINS | Standard verdict | MEDIUM-HIGH |
| Judge: SKEPTIC_WINS | Skeptic verdict | MEDIUM-HIGH (override) |
| Judge: CONTESTED | CONTESTED | LOW (genuine ambiguity) |

### Budget Impact

| Component | Cost |
|-----------|------|
| Skeptic agents | 1 sonnet per HIGH/CRIT finding (~3-8 agents typical) |
| Judge agents | 1 haiku per disagreement (~0-3 agents typical) |
| **Total** | ~3-11 agents (only in Thorough mode) |
