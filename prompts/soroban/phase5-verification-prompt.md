# Phase 5: Verification Prompt Template - Soroban

> **Usage**: Orchestrator reads this file and spawns verification agents for Soroban contract audits.
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
- ~/.claude/agents/skills/soroban/verification-protocol/SKILL.md (if it exists)
- ~/.claude/rules/phase5-poc-execution.md

## PRECISION MODE
You are in PRECISION mode. Your job is to VALIDATE or REFUTE hypotheses with maximum rigor. Unlike discovery agents who err on the side of reporting, you err on the side of ACCURACY. Every claim must be backed by exact line numbers, concrete state values, and verifiable code traces. If you cannot prove exploitation with specific values, say so clearly. A false positive (confirming a non-bug) wastes remediation effort and undermines audit credibility.

## DUAL-PERSPECTIVE VERIFICATION (MANDATORY)

Phase 1 - ATTACKER: Assume you ARE the attacker.
- What's your complete attack sequence (which functions, in what order)?
- What's the profit/damage with real numbers?
- Why would this succeed?

Phase 2 - DEFENDER: Assume you're the contract team.
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
3. **Is the gap documented** in contract docs?
4. **Could the contract achieve the same goal** without this gap?
5. **Does the function fulfill its stated purpose completely?**

**HARD RULE**: If the finding shows Function A has protection X but Function B lacks it for
the same user action → this is a defense parity gap, NOT 'by design'. Minimum severity: Medium.

You may NOT dismiss a defense parity gap as 'Informational' or 'design note'.

## CLASS-CHECK BEFORE FALSE_POSITIVE

Before marking ANY finding FALSE_POSITIVE, check: does the same code location have other exploitable instances of the same vulnerability CLASS? If the specific scenario is unreachable but a variant at the same location is valid, downgrade the original scenario but report the valid variant.

## MANDATORY PoC EXECUTION

Follow `phase5-poc-execution.md`. Compile and run every PoC - a written test with no execution output is not evidence.

**Soroban commands**:
- Compile: `stellar contract build` OR `cargo build --target wasm32v1-none --release`
- Run tests: `cargo test --features testutils` (MUST include `testutils` feature flag)
- Fuzz: `cargo +nightly fuzz run <target>` (only if nightly toolchain installed); on macOS use `cargo +nightly fuzz run --sanitizer=thread <target>` to avoid AddressSanitizer linking errors (see rs-soroban-sdk#1056); fall back to proptest with bounded inputs or boundary-value parameterized tests
- See PoC framework section below for test structure.

### PoC File Placement (MANDATORY — in-crate authoring)

Author the PoC as a **NEW in-crate file** `src/poc_{hypothesis_id}.rs` inside
the target workspace member, wired in via `#[cfg(test)] mod poc_{hypothesis_id};`
added to that member's `lib.rs`. Record in the PoC Attempt Ledger:
- **Test File**: `<crate>/src/poc_{hypothesis_id}.rs`
- **Command**: `cargo test -p <crate> --features testutils {fn}`

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

**TTL / liveness / archival is testable, not structural.** Advance the
ledger via `env.ledger().with_mut(|li| li.sequence_number += N)` and read
the entry's remaining lifetime via `get_ttl()` (instance/persistent/temporary
as applicable) to assert eviction or extension behavior directly.
"`Env::default()` cannot model eviction" is NOT a valid
`STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION` justification for a TTL/archival
finding — the ledger-clock advance above is exactly the tool that models it.

## ANTI-HALLUCINATION RULES

1. You MUST read the actual source files BEFORE writing any test or analysis. Do NOT guess function signatures, parameter types, or return values.
2. You MUST extract real constants from the contract (fee rates, thresholds, TTL values, bounds) and use those in your test. Never invent convenient values.
3. If a function signature differs from what you expected, use the ACTUAL signature from the source code.
4. When tracing code logic, verify the DIRECTION of comparisons (>=, <=, >, <). A >= in an error condition has the opposite meaning from >= in a success condition.
5. Before claiming a state field is 'not updated' by a function, grep for ALL writes to that field across the entire codebase. The function may update it indirectly via a cross-contract call or helper.
6. If you cannot compile or run a test after 5 attempts, provide a MANUAL CODE TRACE with exact line numbers and concrete state transitions. Tag as `[CODE-TRACE]` and set verdict to CONTESTED (not CONFIRMED). A code trace with real values is better than a hallucinated test, but it is NOT mechanical proof.

## SOROBAN SDK ANTI-HALLUCINATION RULES (CRITICAL)

These rules prevent the most common Soroban-specific test failures:

1. **Storage access**: ALWAYS use typed storage methods:
   - `env.storage().instance().get::<K, V>(&key)` NOT `env.storage().get()`
   - `env.storage().persistent().get::<K, V>(&key)`
   - `env.storage().temporary().get::<K, V>(&key)`
   - There is NO global `env.storage().get()` - storage is always accessed via instance/persistent/temporary.

2. **Auth**: `address.require_auth()` - takes NO arguments, called on the Address value itself. NOT `require_auth(&address)`.

3. **Token client**: Must construct client before calling:
   ```rust
   let token = token::Client::new(&env, &token_address);
   token.transfer(&from, &to, &amount);
   ```
   Never call token methods directly. Always construct a client via `token::Client::new()`.

4. **Contract registration** (in tests): Use `env.register(ContractType, ())` NOT `env.register_contract()`. The old API was removed. Example:
   ```rust
   let contract_id = env.register(MyContract, ());
   ```

5. **Auth mocking**: For tests that should not test auth itself:
   - Mock all auth: `env.mock_all_auths()`
   - Mock specific auth: `env.mock_auths(&[MockAuth { address: &addr, invoke: &MockAuthInvoke { contract: &id, fn_name: "my_fn", args: args![&env, arg1, arg2].into_val(&env), sub_invokes: &[] } }])`

6. **Ledger state manipulation**:
   ```rust
   env.ledger().with_mut(|li| {
       li.timestamp = 1000;
       li.sequence_number = 100;
   });
   ```
   NOT `env.ledger().set_timestamp()` - use `with_mut` closure.

7. **Read source FIRST**: Before writing any test, read the actual contract file at `{LOCATION}` to confirm function names, parameter types, storage keys, and error types. The SDK evolves - what worked in Soroban 0.x may not work in 1.x.

## REALISTIC PARAMETER VALIDATION
Substitute ACTUAL contract constants (fee rates, thresholds, TTL values).
Apply Rule 10: Use worst realistic operational state, not current snapshot.
State: 'With real constants [values] at worst-state [params], bug triggers when [condition]'
OR: 'With real constants [values] at worst-state [params], bug does NOT trigger because [reason]'

## PROTOCOL-LEVEL CONTEXT
Consider:
- TVL at risk: what's the maximum extractable value?
- Repeatability: once or continuous?
- User population: one user or all users?
- Storage type risk: instance vs persistent vs temporary — temporary storage expiring mid-operation is a distinct attack class.

## SOROBAN PoC FRAMEWORK (Rust)

### Basic Test Structure

```rust
#![cfg(test)]

use soroban_sdk::{
    testutils::{Address as _, AuthorizedFunction, AuthorizedInvocation, Ledger},
    token, Address, Env, IntoVal,
};

// Import your contract types
use crate::{MyContract, MyContractClient};

#[test]
fn test_exploit_missing_auth() {
    let env = Env::default();
    env.mock_all_auths(); // Remove this line to test auth enforcement

    // 1. REGISTER: Deploy the contract under test
    let contract_id = env.register(MyContract, ());
    let client = MyContractClient::new(&env, &contract_id);

    // 2. SETUP: Create test identities
    let admin = Address::generate(&env);
    let attacker = Address::generate(&env);
    let victim = Address::generate(&env);

    // 3. SETUP: Initialize the contract
    client.initialize(&admin);

    // 4. SETUP: Create and fund token accounts
    let token_admin = Address::generate(&env);
    let sac = env.register_stellar_asset_contract_v2(token_admin.clone());
    let token_client = token::Client::new(&env, &sac.address());
    let token_admin_client = token::StellarAssetClient::new(&env, &sac.address());
    token_admin_client.mint(&victim, &1_000_0000000i128); // 7 decimal places

    // 5. RECORD BEFORE STATE
    let token = token::Client::new(&env, &token_id);
    let balance_before = token.balance(&victim);

    // 6. ATTACK: Execute the exploit WITHOUT victim's auth
    // Remove mock_all_auths and test if attacker can drain without victim signing
    let result = std::panic::catch_unwind(|| {
        client.withdraw_on_behalf(&attacker, &victim, &1_000_0000000i128);
    });

    // 7. VERIFY IMPACT: Check if victim lost funds
    let balance_after = token.balance(&victim);
    assert!(
        balance_after < balance_before,
        "Victim lost {} stroops",
        balance_before - balance_after
    );
}
```

### Auth Verification PoC

```rust
#[test]
fn test_missing_require_auth() {
    let env = Env::default();
    // CRITICAL: Do NOT call env.mock_all_auths() — we need to test real auth enforcement

    let contract_id = env.register(MyContract, ());
    let client = MyContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let attacker = Address::generate(&env);

    client.initialize(&admin);

    // Attempt privileged operation as attacker (should panic with auth error)
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.admin_only_function(&attacker, &some_param);
    }));

    // If result is Ok → auth check is MISSING (bug confirmed)
    // If result is Err → auth check is present (bug refuted)
    assert!(
        result.is_err(),
        "BUG CONFIRMED: admin_only_function succeeded without admin auth"
    );
}
```

### Storage Type Misuse PoC (TTL Expiry)

```rust
#[test]
fn test_temporary_storage_expiry() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(MyContract, ());
    let client = MyContractClient::new(&env, &contract_id);

    // Setup: deposit funds (stored in temporary storage)
    let user = Address::generate(&env);
    client.deposit(&user, &1_000_0000000i128);

    // Simulate ledger advancement past TTL
    env.ledger().with_mut(|li| {
        li.sequence_number += 100_000; // Advance past typical TTL
        li.timestamp += 100_000 * 5;  // ~5 second ledger time
    });

    // Attempt to withdraw - if using temporary storage, entry may have expired
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.withdraw(&user, &1_000_0000000i128);
    }));

    // If result is Err with "missing value" → funds permanently locked (bug confirmed)
    match result {
        Err(_) => println!("BUG CONFIRMED: funds locked after TTL expiry"),
        Ok(_) => println!("Refuted: contract handles TTL expiry correctly"),
    }
}
```

### Integer Overflow PoC

```rust
#[test]
fn test_arithmetic_overflow() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(MyContract, ());
    let client = MyContractClient::new(&env, &contract_id);

    let user = Address::generate(&env);

    // Attempt overflow with i128::MAX values
    // Soroban uses i128 for token amounts - check if intermediate calculations overflow
    let large_amount: i128 = i128::MAX / 2 + 1;

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.calculate_reward(&user, &large_amount, &large_amount);
    }));

    // If panic with 'attempt to multiply with overflow' → unprotected arithmetic
    // If ok with wrong result → wrapping overflow (also a bug)
    println!("Result: {:?}", result);
}
```

### Unprotected Upgrade PoC

```rust
#[test]
fn test_unprotected_upgrade() {
    let env = Env::default();
    // CRITICAL: Do NOT mock auths

    let contract_id = env.register(MyContract, ());
    let client = MyContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let attacker = Address::generate(&env);
    client.initialize(&admin);

    // Prepare a malicious WASM hash
    let malicious_wasm_hash = soroban_sdk::BytesN::from_array(&env, &[0u8; 32]);

    // Attempt upgrade as attacker (not admin)
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.upgrade(&attacker, &malicious_wasm_hash);
    }));

    assert!(
        result.is_err(),
        "BUG CONFIRMED: upgrade succeeded without admin authorization"
    );
}
```

### Cross-Contract Call PoC

```rust
#[test]
fn test_cross_contract_manipulation() {
    let env = Env::default();
    env.mock_all_auths();

    // Register both the target contract and a mock external contract
    let target_id = env.register(TargetContract, ());
    let target = TargetContractClient::new(&env, &target_id);

    // Register a malicious contract that mimics the external interface
    let malicious_id = env.register(MaliciousContract, ());

    // If the target accepts any address as the external contract:
    let attacker = Address::generate(&env);

    // Pass malicious contract address where legitimate external address expected
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        target.do_something_with_external(&attacker, &malicious_id);
    }));

    println!("Cross-contract substitution result: {:?}", result);
}
```

### Ledger Time Manipulation PoC

```rust
#[test]
fn test_timestamp_manipulation() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(MyContract, ());
    let client = MyContractClient::new(&env, &contract_id);

    let user = Address::generate(&env);
    client.start_lock(&user, &1_000_0000000i128);

    // Record state at lock time
    let locked_amount = client.get_locked_amount(&user);

    // Advance ledger timestamp to simulate time passage
    env.ledger().with_mut(|li| {
        li.timestamp = li.timestamp + 7 * 24 * 3600; // +7 days
    });

    // Attempt early withdrawal (should be blocked)
    let unlock_result = client.unlock(&user);

    // Verify: if unlock succeeds before lock period → time check is missing
    println!("Early unlock result: {:?}", unlock_result);
}
```

### Proptest Fuzz Fallback

> Use when nightly toolchain or `cargo-fuzz` is unavailable.

```rust
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use soroban_sdk::Env;

    proptest! {
        #[test]
        fn fuzz_deposit_withdraw(
            amount in 1i128..1_000_000_0000000i128,
            delay_blocks in 0u32..100_000u32
        ) {
            let env = Env::default();
            env.mock_all_auths();

            let contract_id = env.register(MyContract, ());
            let client = MyContractClient::new(&env, &contract_id);

            let user = soroban_sdk::Address::generate(&env);
            client.deposit(&user, &amount);

            env.ledger().with_mut(|li| {
                li.sequence_number += delay_blocks; // sequence_number is u32
            });

            // Invariant: withdraw should return same amount deposited (minus fees)
            let withdrawn = client.withdraw(&user);
            prop_assert!(withdrawn <= amount, "Withdrew more than deposited");
        }
    }
}
```

## ERROR TRACE OUTPUT
When verdict is CONTESTED or FALSE_POSITIVE, document:

### Error Trace
- **Failure Type**: PANIC / AUTH_ERROR / CONTRACT_ERROR / INSUFFICIENT_EVIDENCE / COMPILE_ERROR
- **Location**: {contract}:{function}:{line where failure occurs}
- **Error Value**: {Soroban error code or panic message, if any}
- **State at Failure**: {key storage values and ledger state when the test failed}
- **Investigation Question**: {What specific question would need to be answered to resolve this}

## NEW OBSERVATIONS (MANDATORY)
If during verification you discover a NEW bug, configuration dependency, or edge case
NOT covered by any existing hypothesis - document it under:

### New Observations
- [VER-NEW-1]: {title} - {location} - {brief description}

These will be reviewed by the orchestrator for possible inclusion as new findings.

## COMMITTED-INVARIANT EMISSION (MANDATORY — value-bearing REFUTED/CLEAR)

Whenever your verdict REFUTES or CLEARS a value-bearing path (value movement,
supply/shares, accounting, authorization, or a funds/liveness-gating boundary) —
i.e. a FALSE_POSITIVE or otherwise-safe judgment on a value-bearing finding — you
MUST additionally emit a `committed-invariant [CI-n]` block naming the local guard
that makes the path safe. This is the Code-Augur "commit the invariant behind
every safe judgment" locus: verify is a rich reservoir of concluded-safe verdicts,
so it is now a PRIMARY CI emitter alongside depth. Emit exactly ONE of the six
generic SHAPES — `CONSERVATION`, `REQUESTED_EQ_DELIVERED`, `APPROVE_EQ_SPEND`,
`NO_REVERT_AT_BOUNDARY`, `ROUNDTRIP`, `FRESHNESS` — with symbols resolved at the
locus but no protocol constant baked as "the answer":

```
committed-invariant [CI-n]
Locus: <file>:L<nn>  (fn: <enclosing function>)
Shape: <one of the six shapes>
Assertion: <the falsifiable relation, symbols resolved>
Falsify Class: <property | boundary | roundtrip | conservation>
Provenance: verify REFUTED/CLEAR @ <hypothesis id>
```

This is MANDATORY for every value-bearing REFUTED/CLEAR verdict and strictly
additive — it changes no verdict, severity, or prior finding. A non-value-bearing
CLEAR (pure view, no funds/liveness/accounting/authorization stake) does not
require a block. Emitted blocks are written into `verify_{hypothesis_id}.md` and
mechanically harvested downstream into falsifiable candidates for the fuzz/PoC
gates. The six shapes are generic relational forms; NEVER encode a specific
protocol/token/function as "the answer" — symbols resolve at the locus at runtime.

**FALSIFIABILITY-AWARE SHAPE SELECTION (MANDATORY).** Emit the shape whose
falsifier could actually FAIL at this locus. If the shape you first reach for is
*true by construction* — its assertion cannot be violated by any reachable input
because the code trivially satisfies it (for example a 1:1 unwrap step
trivially satisfies `CONSERVATION`, so a conservation falsifier can never break)
— that block is worthless as a downstream PoC target. In that case you MUST ALSO
add at least one shape that CAN break at the same locus: a
`NO_REVERT_AT_BOUNDARY` block (does the boundary/limit case revert, brick, or
mis-round?) and/or a `REQUESTED_EQ_DELIVERED` block (does the amount/asset the
caller requested equal what the callee actually delivered, across a
conversion/bridge/wrap boundary?). You MAY emit **2–3 CI blocks per locus** for
exactly this reason — one per distinct falsifiable relation. This is a generic
HOW-directive about picking a *breakable* invariant; it names no protocol, token,
or function (a native↔wrapped conversion is only an illustrative example of a
boundary where `CONSERVATION` looks satisfied yet `REQUESTED_EQ_DELIVERED` can
still diverge). Symbols always resolve at the locus at runtime.

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
