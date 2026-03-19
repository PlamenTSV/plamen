# Phase 4b: Invariant Fuzz Generator - Solana/Anchor (v1.1.0)

> **Purpose**: LLM-generated Trident invariant tests targeting protocol-specific economic invariants, lifecycle correctness, finding-derived fuzz targets, and structural consistency - derived from the audited codebase's actual design, not generic templates.
> **Model**: sonnet | **Budget**: 0 depth slots (1 sonnet agent + Trident execution)
> **Trigger**: `semantic_invariants.md` exists AND `trident_available: true` in `build_status.md`. **Skip** if false → proptest fallback in Phase 5.
> **Time cap**: 5min shell timeout. Trident v0.11+ uses TridentSVM (no honggfuzz/AFL).
> **Execution cost**: Zero token cost regardless of invariant/handler count. NO reason to cap.

---

## Generator Agent Template

```
Task(subagent_type="general-purpose", model="sonnet", prompt="
You are the Solana Invariant Fuzz Generator. You derive protocol-specific invariants from the audit artifacts and translate them into Trident fuzz tests, run them, and report violations.

## Your Inputs
Read ALL of these - each source contributes different invariant types:
- {SCRATCHPAD}/design_context.md (protocol purpose, key invariants, trust model - PRIMARY source for economic invariants)
- {SCRATCHPAD}/findings_inventory.md (critical findings - each Medium+ finding should become a fuzz target)
- {SCRATCHPAD}/semantic_invariants.md (write sites, sync gaps, clusters - source for structural invariants)
- {SCRATCHPAD}/state_variables.md (account structures, types)
- {SCRATCHPAD}/function_list.md (program instructions - these become FuzzInstruction handlers)
- {SCRATCHPAD}/contract_inventory.md (program paths)
- {SCRATCHPAD}/constraint_variables.md (parameter bounds, fees, limits - source for value ranges)
- Source files referenced in the above artifacts
- ~/.claude/agents/skills/solana/trident-api-reference/SKILL.md (correct API signatures - MUST read before writing any code)

## STEP 0.5: Scope Selection

- **Foundation** (always): Single-program invariants, all instruction handlers from primary program
- **Integration** (if CPI detected): Add cross-program sequences, CPI target handlers as FuzzInstruction variants
- **Temporal** (if clock/timestamp usage): Add clock advancement, epoch-boundary assertions (slot 0, far-future)

## STEP 1: Derive Invariants (NO CAP - test everything meaningful)

Write as many invariant assertions as the protocol has meaningful state properties. Do NOT artificially limit.

### 1a. Protocol-Specific Economic Invariants (from design_context.md)

Read the protocol's stated purpose and key invariants from design_context.md. For EACH key invariant or design goal, write a Rust assertion. These are the MOST VALUABLE invariants - they test what the protocol is SUPPOSED to do.

Examples of what to derive:
- Lending protocol: `assert!(total_borrows <= total_deposits)`
- Vault: `assert!(share_price_after >= share_price_before)` (absent losses)
- DEX: `assert!(k_after >= k_before)` (constant product preserved after swaps)
- Staking: `assert!(total_staked == individual_stakes_sum)`
- LP pool: `assert!(lp_supply > 0 || (reserve_a == 0 && reserve_b == 0))`

### 1b. Finding-Derived Invariants (from findings_inventory.md)

For EACH Medium+ finding in findings_inventory.md, ask: 'What invariant would CATCH this bug mechanically?' Write that invariant.

Examples:
- Finding: 'withdrawal skips interest accrual' -> `assert!(accrued_interest_after >= accrued_interest_before)` in withdraw handler
- Finding: 'PDA authority can be reassigned' -> `assert!(authority_after == authority_before || signer == current_authority)`
- Finding: 'stake account closed with pending rewards' -> `assert!(pending_rewards == 0)` before close
- Finding: 'overflow in reward calculation' -> `assert!(reward_per_token <= u64::MAX / total_stakers)`

### 1c. Lifecycle Invariants (from function_list.md)

For each major lifecycle in the protocol (initialize->deposit->withdraw, create->close, stake->unstake), write an invariant that verifies the lifecycle returns to a consistent state:
- After a complete cycle, net token deltas should be zero (minus fees)
- No accounts should be permanently stuck (stranded token accounts, orphaned PDAs)
- Reversible operations should actually reverse
- Close instructions should return all lamports to the owner

### 1d. Structural Invariants (from semantic_invariants.md)

For each SYNC_GAP, CONDITIONAL, ACCUMULATION_EXPOSURE, and CLUSTER_GAP flag:
- Mirror variables stay synchronized across accounts
- Conditional writes don't leave stale state in skip path
- Accumulators stay bounded
- Cluster partial-writes don't break cross-account invariants

### 1e. Boundary Invariants (from constraint_variables.md)

For each constraint variable (min/max/cap/limit/fee/rate):
- Values stay within documented bounds after any sequence of instructions
- Edge cases (0, 1, u64::MAX) don't corrupt accounting
- Fee calculations don't overflow or underflow
- Zero-amount operations don't corrupt state

### Invariant Quality Self-Check (before writing code)
For each selected invariant, verify:
- **Not tautological**: Can you trace both sides of the assertion to DIFFERENT write sites? If both sides come from the same write in the same instruction, the invariant always passes trivially - discard it.
- **Sensitive**: Would a real bug (e.g., missing state update, skipped balance check) actually violate this assertion? If the invariant holds even when the code is wrong, it detects nothing - discard it.
- **Testable**: Can the assertion be evaluated using only on-chain account state readable via AccountsStorage? If it requires off-chain data or complex deserialization beyond account data, skip it.

### Output Table
For each invariant, write:
| # | Source | Category | Invariant (English) | Assertion (Rust) |

## STEP 2: Account Dependency Mapping

Before writing handlers, map the account dependency graph:

| Instruction | Required Accounts | Prerequisites (must exist first) | PDA Seeds |
|------------|-------------------|----------------------------------|-----------|

### Hidden Prerequisites Checklist
For each instruction handler, verify:
- [ ] Does this instruction require a counter/nonce > 0? (setup must increment first)
- [ ] Does this instruction check a supply/balance gate? (setup must provide tokens)
- [ ] Does this instruction use AccountLoader (zero-copy)? (account must be pre-allocated with correct size)
- [ ] Does this instruction require a specific account discriminator? (use correct init instruction first)
- [ ] Are there optional-but-required accounts? (accounts marked Optional in IDL but panics without them)
- [ ] Does this instruction require a signer that is also a PDA? (CPI signer seeds needed)

## STEP 3: Generate Fuzz Handlers

Customize `trident-tests/fuzz_tests/fuzz_0/fuzz_instructions.rs`:

### Handler Rules:
- Bound all numeric params: `let amount = data.amount % MAX_REASONABLE_AMOUNT;`
- Use the Snapshot pattern for pre/post state comparison (see TRIDENT_API_REFERENCE.md)
- Add invariant checks in the `check_invariant` hook - panic on violation
- Include ALL program instructions as FuzzInstruction variants - more handlers = better state space
- For time-dependent invariants: advance clock between instruction sequences
- For PDA-dependent handlers: compute seeds correctly using the program's actual derivation logic
- Use `constraint_variables.md` for protocol-specific bounds (max amounts, fee caps, rate limits)
- Include at least 2 distinct user signers for multi-actor scenarios

### Lifecycle Sequence Handlers (MANDATORY for protocols with multi-step operations):
- Identify every lifecycle in the protocol (e.g., initialize->deposit->withdraw->close)
- Write at least 1 handler that executes the FULL sequence atomically
- Write at least 1 handler that executes a PARTIAL sequence (enters but doesn't exit)
- These are critical because random individual handlers rarely construct valid multi-step state

### Non-Triviality Verification (MANDATORY)
After generating handlers, add these meta-checks to the test harness:
```rust
// Track execution statistics
static CALLS_EXECUTED: AtomicU64 = AtomicU64::new(0);
static CALLS_SUCCEEDED: AtomicU64 = AtomicU64::new(0);

// In each handler's post-execution:
CALLS_EXECUTED.fetch_add(1, Ordering::Relaxed);
if result.is_ok() { CALLS_SUCCEEDED.fetch_add(1, Ordering::Relaxed); }

// After campaign: check success rate
// Optimal: 40-60% success rate (some reverts expected, but state is actually changing)
// Broken: 0% success (nothing executed - setup error)
// Weak: <10% success (most paths blocked - missing prerequisites)
```

If ALL handlers revert (0% success rate), report: `[FUZZ-EMPTY] - campaign trivially empty, setup error likely. Zero confidence.`

### Handler Template (per instruction):
```rust
impl InstructionNameHandler for FuzzInstruction {
    fn get_data(&self) -> Result<InstructionNameData, FuzzingError> {
        // Bound params to realistic ranges from constraint_variables.md
        Ok(InstructionNameData { amount: data.amount % 1_000_000_000_000, .. })
    }
    fn get_accounts(&self, fuzz_accounts: &mut FuzzAccounts) -> Result<Vec<AccountMeta>, FuzzingError> {
        // Map AccountId fields to addresses; use correct PDA derivation
        Ok(vec![/* account metas */])
    }
}
```

## STEP 4: Initialize and Run Campaign

```bash
# Windows: auto-detect OpenSSL (required for Trident compilation)
if [[ \"$OSTYPE\" == \"msys\" || \"$OSTYPE\" == \"cygwin\" ]] && [ -z \"$OPENSSL_DIR\" ]; then
  for base in \"/c/Program Files/OpenSSL-Win64\" \"/c/Program Files/OpenSSL\"; do
    if [ -d \"$base/include/openssl\" ]; then
      export OPENSSL_DIR=\"$base\" OPENSSL_LIB_DIR=\"$base/lib/VC/x64/MD\" OPENSSL_INCLUDE_DIR=\"$base/include\"
      break
    fi
  done
fi
# Initialize if trident-tests/ does not exist
pushd {PROJECT_ROOT} && trident init --skip-build 2>&1 | tail -10
# Run campaign (v0.11+ TridentSVM - no honggfuzz needed); 5-min timeout
pushd {PROJECT_ROOT}/trident-tests && timeout 300 trident fuzz run fuzz_0 2>&1 | tail -50
```

If compilation or init fails: read error, apply targeted fix, retry ONCE. If still fails: report `COMPILATION_FAILED`, skip execution.

### Post-Campaign: Check for Violations
```bash
ls -la {PROJECT_ROOT}/trident-tests/.fuzz-artifacts/ 2>/dev/null
# If violations found, re-run with specific seed for reproduction
pushd {PROJECT_ROOT}/trident-tests && trident fuzz run fuzz_0 <SEED_FROM_OUTPUT> 2>&1
```

## STEP 5: Report Results

Write to {SCRATCHPAD}/invariant_fuzz_results.md:

```markdown
# Invariant Fuzz Results (Solana/Trident)

## Campaign Summary
- Invariants tested: {N}
- Handlers: {H} individual + {L} lifecycle sequence
- Iterations: {runs}
- Violations found: {V}
- Compilation: SUCCESS/FAILED (reason)
- Success rate: {pct}% ({succeeded}/{total} calls)
- Non-triviality: VERIFIED / [FUZZ-EMPTY]

## Category Coverage
| Category | Count | Source | Covered? |
|----------|-------|--------|----------|
| Protocol-specific economic | {n} | design_context.md | YES/NO |
| Finding-derived | {n} | findings_inventory.md | YES/NO |
| Lifecycle completion | {n} | function_list.md | YES/NO |
| Structural consistency | {n} | semantic_invariants.md | YES/NO |
| Boundary/edge-case | {n} | constraint_variables.md | YES/NO |

## Invariant Results
| # | Invariant | Category | Status | Counterexample | Related Finding |
|---|-----------|----------|--------|---------------|----------------|

## Violations (Findings)
For each violation, use standard finding format with [FUZZ-N] IDs:
- Include counterexample call sequence from crash file debug output
- Map to existing findings where applicable
- Severity: use standard matrix (invariant violations on core accounting = High likelihood)
- Evidence tag: [TRIDENT-FUZZ] (mechanical proof, same weight as [POC-PASS])
```

If NO violations found: write summary with 'No violations detected in {runs} iterations across {N} invariants' and return.
Violations become depth agent input - they provide concrete counterexamples for investigation.

Return: 'DONE: {N} invariants tested ({categories} categories), {H} handlers, {V} violations found, success rate {pct}%'
")
```

---

## Fallback: proptest Boundary Tests (when Trident unavailable)

When `trident_available: false`, the invariant fuzz campaign is skipped entirely at this phase.
Proptest or boundary-value parameterized tests are used instead during Phase 5 verification
(see `~/.claude/rules/phase5-poc-execution.md` - Non-EVM Fuzz Guidance).

This is NOT a failure - native Solana programs without Anchor IDLs cannot use Trident.
The Phase 5 proptest fallback provides per-finding fuzz coverage with bounded inputs.
