# Phase 4b: Invariant Fuzz Generator (v1.1.0)

> **Purpose**: LLM-generated Foundry invariant tests targeting protocol-specific economic invariants, lifecycle correctness, and structural consistency - derived from the audited codebase's actual design, not generic templates.
> **Model**: sonnet (mechanical generation task - translates invariants into Solidity test code)
> **Budget**: 0 depth slots (runs between semantic invariants and depth agents; cost = 1 sonnet agent + forge execution)
> **Trigger**: Always runs when `semantic_invariants.md` exists AND `foundry.toml` exists in project root.
> **Skip**: If project uses Hardhat only (no `foundry.toml`) → skip entirely. Hardhat has no native invariant test support.
> **Execution cost**: Forge test execution is a Bash tool call - zero token cost regardless of invariant count, handler count, or run count. There is NO reason to cap the number of invariants or handlers.

---

## Generator Agent Template

```
Task(subagent_type="general-purpose", model="sonnet", prompt="
You are the Invariant Fuzz Generator. You derive protocol-specific invariants from the audit artifacts and translate them into Foundry invariant tests.

## Your Inputs
Read ALL of these - each source contributes different invariant types:
- {SCRATCHPAD}/design_context.md (protocol purpose, key invariants, trust model - PRIMARY source for economic invariants)
- {SCRATCHPAD}/findings_inventory.md (critical findings - each Medium+ finding should become a fuzz target)
- {SCRATCHPAD}/semantic_invariants.md (write sites, sync gaps, clusters - source for structural invariants)
- {SCRATCHPAD}/state_variables.md (variable types, contracts)
- {SCRATCHPAD}/function_list.md (public/external functions - handler targets)
- {SCRATCHPAD}/contract_inventory.md (contract paths, inheritance)
- {SCRATCHPAD}/constraint_variables.md (parameter bounds, fees, limits - source for value ranges)
- Source files referenced in the above artifacts

## STEP 1: Derive Invariants (NO CAP - test everything meaningful)

Forge execution is zero token cost regardless of invariant count. Write as many `invariant_` functions as the protocol has meaningful properties. Do NOT artificially limit to 8 or any number.

### 1a. Protocol-Specific Economic Invariants (from design_context.md)

Read the protocol's stated purpose and key invariants from design_context.md. For EACH key invariant or design goal, write a Solidity assertion. These are the MOST VALUABLE invariants - they test what the protocol is SUPPOSED to do.

Examples of what to derive:
- Lending protocol: 'total borrows <= total deposits'
- Vault: 'share price is monotonically non-decreasing (absent losses)'
- DEX: 'k = x * y is preserved after swaps'
- Staking: 'total staked == sum of individual stakes'
- Credit protocol: 'total CREDIT supply == sum of collateral backing'

### 1b. Finding-Derived Invariants (from findings_inventory.md)

For EACH Medium+ finding in findings_inventory.md, ask: 'What invariant would CATCH this bug mechanically?' Write that invariant.

Examples:
- Finding: 'loan closure reverts due to interest' -> `invariant_loansAlwaysCloseable()`
- Finding: 'CREDIT burn uses wrong amount' -> `invariant_creditBurnMatchesActualRedemption()`
- Finding: 'originalOwner overwritten' -> `invariant_originalOwnerPreserved()`
- Finding: 'sub-account overflow at 156' -> `invariant_subAccountIdBounded()`

### 1c. Lifecycle Invariants (from function_list.md)

For each major lifecycle in the protocol (deposit->withdraw, borrow->repay, create->close), write an invariant that verifies the lifecycle returns to a consistent state:
- After a complete cycle, net token deltas should be zero (minus fees)
- No state should be permanently stuck (locked tokens, orphaned records)
- Reversible operations should actually reverse

### 1d. Structural Invariants (from semantic_invariants.md)

For each SYNC_GAP, CONDITIONAL, ACCUMULATION_EXPOSURE, and CLUSTER_GAP flag:
- Mirror variables stay synchronized
- Conditional writes don't leave stale state
- Accumulators stay bounded
- Cluster partial-writes don't break cross-variable invariants

### 1e. Boundary Invariants (from constraint_variables.md)

For each constraint variable (min/max/cap/limit/fee/rate):
- Values stay within documented bounds after any sequence of operations
- Edge cases (0, 1, MAX) don't break accounting
- Fee calculations don't overflow or underflow

### Output Table
For each invariant, write:
| # | Source | Category | Invariant (English) | Assertion (Solidity) |

## STEP 2: Generate Handler Contract

Write a Foundry test file to {PROJECT_ROOT}/test/invariant/InvariantFuzz.t.sol:

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import \"forge-std/Test.sol\";
// Import target contracts based on contract_inventory.md

contract Handler is Test {
    // Target contract instances (initialized in setUp)

    // === Individual function handlers ===
    // For EVERY public/external state-mutating function on target contracts:
    // function handler_functionName(bounded params) external {
    //     // Bound params to REALISTIC ranges (see value bounds below)
    //     // Call target function inside try/catch
    // }

    // === Lifecycle sequence handlers (CRITICAL) ===
    // These construct realistic multi-step state that individual handlers cannot:
    //
    // function handler_fullLifecycle(bounded params) external {
    //     // Step 1: Setup (deploy, approve, configure)
    //     // Step 2: Enter position (deposit, borrow, stake)
    //     // Step 3: Time passes (vm.warp)
    //     // Step 4: Exit position (repay, withdraw, unstake)
    //     // Step 5: Verify cleanup (no stuck state)
    // }
    //
    // function handler_partialLifecycle(bounded params) external {
    //     // Setup -> enter -> partial action -> leave mid-state
    //     // Tests what happens when users abandon positions
    // }
}

contract InvariantFuzz is Test {
    Handler handler;
    // Target contract instances

    function setUp() public {
        // Deploy target contracts with minimal valid configuration
        // Deploy handler with target references
        // targetContract(address(handler));
        // targetSelector -- include all handler functions
    }

    // function invariant_protocolInvariant() public view {
    //     // Assert the protocol-specific invariant
    // }
}
```

### Handler Rules

**Value bounds** -- use protocol-realistic ranges, not arbitrary caps:
- Token amounts: `bound(amount, 1, 1_000_000 * 10**decimals)` -- match the token's actual decimals
- Fees/rates: `bound(fee, 0, 10_000)` for basis points, `bound(rate, 0, 1e18)` for WAD
- Time deltas: `bound(dt, 1, 365 days)` for interest accrual, `bound(dt, 0, 7 days)` for operational
- Array indices: `bound(idx, 0, currentLength - 1)` -- avoid out-of-bounds
- Addresses: use `makeAddr('userN')` for distinct users, `bound(seed, 1, 10)` to limit actor count
- Read `constraint_variables.md` for protocol-specific bounds (max loan amounts, LTV ratios, fee caps)

**Handler function rules**:
- Include ALL public/external state-mutating functions -- no cap on handler count
- Use `try/catch` for external calls -- handlers must not revert (reverts hide bugs)
- Include `vm.warp(bound(dt, 1, 365 days))` handlers for time-dependent protocols
- Include `deal()` or `mint()` for token balance setup where needed
- Include `vm.prank(user)` for multi-actor scenarios -- at least 2 distinct users
- Include lifecycle sequence handlers that execute full create->use->close flows

**Lifecycle sequence handlers** (MANDATORY for protocols with multi-step operations):
- Identify every lifecycle in the protocol (e.g., deposit->borrow->repay->close)
- Write at least 1 handler that executes the FULL sequence atomically
- Write at least 1 handler that executes a PARTIAL sequence (enters but doesn't exit)
- These are critical because random individual handlers rarely construct valid multi-step state

## STEP 3: Compile and Run Campaign

First compile:
```bash
cd {PROJECT_ROOT} && forge build 2>&1 | tail -30
```

If compilation fails: read error, fix imports/types/remappings, retry (max 3 attempts). If still fails: report compilation error, skip execution, and return early.

Then run -- 256 runs x depth 25 (typically 3-10 minutes, zero token cost for more runs):
```bash
cd {PROJECT_ROOT} && timeout 600 forge test --match-contract InvariantFuzz --invariant-runs 256 --invariant-depth 25 --fail-on-revert false -vv 2>&1 | head -300
```

On Windows (no timeout command -- forge's internal run cap handles it):
```bash
cd {PROJECT_ROOT} && forge test --match-contract InvariantFuzz --invariant-runs 256 --invariant-depth 25 --fail-on-revert false -vv 2>&1 | head -300
```

If execution takes >10 minutes, the 256-run cap will terminate it. More runs = better coverage at zero token cost.

## STEP 4: Report Results

Write to {SCRATCHPAD}/invariant_fuzz_results.md:

```markdown
# Invariant Fuzz Results

## Campaign Summary
- Invariants tested: {N}
- Handlers: {H} individual + {L} lifecycle sequence
- Runs: {runs} x depth {depth} = {total_sequences} call sequences
- Violations found: {V}
- Compilation: SUCCESS/FAILED (reason)

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
- Include the counterexample call sequence from forge output
- Map to existing findings where applicable
- Severity: use standard matrix (invariant violations on core accounting = High likelihood)
- Evidence tag: [POC-PASS] (mechanical proof via executed test)
```

If NO violations found: write summary with 'No violations detected in {runs} runs across {N} invariants' and return.
Violations become depth agent input -- they provide concrete counterexamples for investigation.

Return: 'DONE: {N} invariants tested ({categories} categories), {H} handlers, {V} violations found'
")
```
