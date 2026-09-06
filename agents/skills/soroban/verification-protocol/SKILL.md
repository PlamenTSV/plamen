---
name: "verification-protocol"
description: "Trigger Pattern Always (used by all verifier agents) - Inject Into security-verifier agents (Phase 5)"
---

# VERIFICATION_PROTOCOL Skill (Soroban)

> **Trigger Pattern**: Always (used by all verifier agents)
> **Inject Into**: security-verifier agents (Phase 5)
> **Purpose**: Prove hypotheses TRUE or FALSE using `cargo test` with `soroban-sdk` testutils and the `Env` harness.

---

## Evidence Source Tracking (MANDATORY)

> **CRITICAL**: For EVERY piece of evidence, tag its source. Evidence from mocks or unverified external contracts CANNOT support a REFUTED verdict.

| Tag | Meaning | Valid for REFUTED? |
|-----|---------|-------------------|
| `[PROD-ONCHAIN]` | Production Stellar account/contract data (Horizon RPC / `stellar contract read`) | YES |
| `[PROD-SOURCE]` | Verified source from Stellar Explorer / published audit | YES |
| `[PROD-FORK]` | Tested with forked production state via `stellar-quickstart` | YES |
| `[CODE]` | Audited codebase (in-scope source) | YES |
| `[MOCK]` | Mock contracts or test-only state in `testutils` | **NO** |
| `[EXT-UNV]` | External contract behavior inferred but not verified | **NO** |
| `[DOC]` | Documentation/spec only | **NO** |

### Evidence Audit Table (REQUIRED in every verification output)

```markdown
### Evidence Audit
| Claim | Evidence Source | Tag | Valid for REFUTED? |
|-------|-----------------|-----|-------------------|
```

### Mock Rejection Rule

If ANY evidence supporting REFUTED has tag `[MOCK]` or `[EXT-UNV]`: CANNOT return REFUTED, MUST return CONTESTED, triggers production verification request.

---

## Pre-Verification Understanding

Before writing ANY test code, answer these three questions:

1. **What is the EXACT bug?** -- Not "Authorization is missing" but "Function [withdraw] does not call env.require_auth(&user) before modifying user balances, allowing any caller to withdraw funds (src/lib.rs:line N)"
2. **What OBSERVABLE difference proves it?** -- Concrete before/after values in stroops, expected behavior
3. **What is the EXACT assertion?** -- e.g., `assert_eq!(client.balance(&attacker), initial_user_balance)` or `assert!(result.is_err(), "should have panicked")`

**If you cannot answer all three -> ASK FOR CLARIFICATION**

---

## Pre-PoC Feasibility Gates (MANDATORY)

### Gate F1: Reachability
- [ ] Entry point identified (public `#[contractimpl]` function)
- [ ] Call path traced through internal helpers
- [ ] All `require_auth` checks passable by attacker profile

If NO public entry point -> UNREACHABLE -> FALSE_POSITIVE.
If reachable only through admin-gated path -> document restriction, adjust likelihood.

### Gate F2: Math Bounds
- [ ] Parameter domains identified (7 decimals for XLM, max supply, TVL range, fee range, ledger bounds)
- [ ] Expression evaluated at worst-case feasible inputs
- [ ] Result crosses the bug threshold

If values outside feasible domains -> INFEASIBLE -> FALSE_POSITIVE.

**Both gates PASS -> proceed to PoC. Either gate FAILS -> document and stop.**

---

## Soroban Anti-Hallucination Rules (MANDATORY)

Verify EVERY API call against these known-correct patterns. Do NOT assume Solana/EVM API shapes apply.

```rust
// Environment
let env = Env::default();               // NOT: Env::new(), TestEnv::default()

// Auth mocking
env.mock_all_auths();                   // Disables ALL auth — for logic tests, NOT auth tests
env.mock_auths(&[MockAuth { ... }]);    // Specific auth — for auth flow tests

// Contract registration
let contract_id = env.register(ContractType, ());             // No constructor args
let contract_id = env.register(ContractType, (arg1, arg2,));  // With args
// NOT: env.register_contract(), env.deploy_contract()

// Addresses
let user = Address::generate(&env);     // NOT: Address::random(), Pubkey::new_unique()

// Token client (SAC-compatible)
let token_admin = Address::generate(&env);
let (token_address, token_admin_client) = create_token_contract(&env, &token_admin);
let token_client = token::Client::new(&env, &token_address);

// Ledger manipulation
env.ledger().with_mutation(|l| {
    l.sequence_number = 100;
    l.timestamp = 1_000_000;
});
// NOT: env.set_ledger_sequence(), env.advance_ledger()

// Reading contract storage
let val: T = env.as_contract(&contract_id, || {
    env.storage().persistent().get(&DataKey::MyKey).unwrap()
});

// Client invocation
let client = ContractClient::new(&env, &contract_id);
client.my_function(&arg1, &arg2);

// Expecting a panic
let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
    client.my_function(&arg1, &arg2)
}));
assert!(result.is_err());

// Storage: persistent (user data), instance (contract-level), temporary (expires on TTL)
env.storage().persistent().set(&key, &value);  // .get::<K,V>(), .has()
env.storage().instance().set(&key, &value);    // same API
env.storage().temporary().set(&key, &value);   // same API

// Auth (production code — what to test against)
env.require_auth(&address);                              // basic
env.require_auth_for_args(&address, args!(arg1, arg2));  // with args
let auths = env.auths();  // Vec<(Address, AuthorizedInvocation)>
```

---

## Soroban PoC Test Templates

### Template 1: Missing Authorization Check

```rust
#[test]
fn test_missing_auth_attacker_can_drain() {
    let env = Env::default();
    // Do NOT call env.mock_all_auths() — testing that auth IS required
    let (admin, user, attacker) = (Address::generate(&env), Address::generate(&env), Address::generate(&env));
    let contract_id = env.register(MyContract, (&admin,));
    let client = MyContractClient::new(&env, &contract_id);

    // Setup: mock admin auth for setup only
    env.mock_auths(&[MockAuth {
        address: &admin,
        invoke: &MockAuthInvoke {
            contract: &contract_id, fn_name: "fund_user",
            args: (&user, &1000_i128).into_val(&env), sub_invokes: &[],
        },
    }]);
    client.fund_user(&user, &1000_i128);

    // EXPLOIT: attacker withdraws without user's auth — if auth missing, succeeds
    client.withdraw(&attacker, &user, &1000_i128);
    assert_eq!(client.balance(&user), 0_i128, "user drained");
    assert_eq!(client.balance(&attacker), 1000_i128, "attacker stole funds");
}
```

### Template 2: Storage Key Collision / Schema Mismatch

```rust
#[test]
fn test_storage_key_collision_wrong_deserialization() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(MyContractV2, ());
    let client = MyContractV2Client::new(&env, &contract_id);

    // Write V1 format data manually (migration scenario)
    env.as_contract(&contract_id, || {
        env.storage().persistent().set(&DataKey::UserBalance,
            &OldDataStruct { field_a: 100_i128, field_b: 50_u64 });
    });

    // V2 reads V1 data — should trap or return corrupted value
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| client.get_user_balance()));
    if let Ok(balance) = result {
        assert_ne!(balance, 100_i128, "Silent data corruption from wrong type");
    } // If Err: deserialization trapped — contract bricked for V1 data
}
```

### Template 3: Reentrancy / State Inconsistency

```rust
#[test]
fn test_reentrancy_state_inconsistency() {
    let env = Env::default();
    env.mock_all_auths();

    let attacker_id = env.register(AttackerContract, ());
    let victim_id = env.register(VictimContract, (&Address::generate(&env),));
    let victim_client = VictimContractClient::new(&env, &victim_id);
    let attacker_client = AttackerContractClient::new(&env, &attacker_id);

    let balance_before = victim_client.total_deposits();
    attacker_client.execute_reentrancy_attack(&victim_id);
    let balance_after = victim_client.total_deposits();

    assert!(attacker_client.profit() > 0, "Reentrancy should be profitable");
    assert!(balance_after < balance_before, "Victim drained: before={}, after={}",
        balance_before, balance_after);
}
```

### Template 4: Arithmetic Overflow / Precision Loss

```rust
#[test]
fn test_arithmetic_precision_loss_at_boundary() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(VaultContract, ());
    let client = VaultContractClient::new(&env, &contract_id);
    let user_a = Address::generate(&env);
    let user_b = Address::generate(&env);

    // XLM: 7 decimal places (1 XLM = 10_000_000 stroops)
    client.deposit(&user_a, &1_i128);                        // 1 stroop
    client.deposit(&user_b, &10_000_000_000_000_i128);       // 1M XLM

    let user_a_shares = client.shares(&user_a);
    let user_a_withdraw = client.withdraw(&user_a, &user_a_shares);

    assert_eq!(user_a_withdraw, 1_i128,
        "User A lost deposit to rounding: received {}", user_a_withdraw);
}
```

### Template 5: Ledger Sequence / Timestamp Manipulation

```rust
#[test]
fn test_cooldown_bypass_same_ledger_sequence() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(CooldownContract, ());
    let client = CooldownContractClient::new(&env, &contract_id);
    let user = Address::generate(&env);

    env.ledger().with_mutation(|l| { l.sequence_number = 100; l.timestamp = 1_000_000; });
    client.action(&user);

    // Same ledger — Soroban consecutive ledgers CAN have same timestamp
    env.ledger().with_mutation(|l| { l.sequence_number = 100; l.timestamp = 1_000_000; });

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.action(&user)
    }));
    assert!(result.is_err(), "Cooldown bypassed in same ledger");
}
```

### Template 6: try_invoke_contract Partial State

```rust
#[test]
fn test_try_invoke_partial_state_on_external_error() {
    let env = Env::default();
    env.mock_all_auths();

    let failing_external = env.register(FailingExternalContract, ());
    let contract_id = env.register(ProtocolContract, (&failing_external,));
    let client = ProtocolContractClient::new(&env, &contract_id);
    let user = Address::generate(&env);

    let initial = client.recorded_deposit(&user);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.deposit(&user, &1000_i128)
    }));

    if result.is_ok() {
        assert_eq!(client.recorded_deposit(&user), initial,
            "Partial state: deposit recorded despite external failure");
    }
}
```

---

## Fuzz Variant (Medium+, Soroban-specific)

> Build/test commands and fallback logic are in phase5-poc-execution.md. Below: Soroban-specific harness patterns.

**cargo-fuzz** (nightly): Use `Env::default()` + `mock_all_auths()` + `env.register()` in harness. Derive fuzz inputs from `&[u8]` via `i128::from_le_bytes`. Assert invariants inside `catch_unwind`. Run: `cargo +nightly fuzz run fuzz_target_1 -- -max_total_time=300`

**proptest** (stable fallback):
```rust
proptest! {
    #[test]
    fn test_fuzz_invariant(amount in 1_i128..1_000_000_000_000_i128, seq in 1_u32..100_000_u32) {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().with_mutation(|l| { l.sequence_number = seq; });
        let contract_id = env.register(MyContract, ());
        let client = MyContractClient::new(&env, &contract_id);
        let user = Address::generate(&env);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.target_function(&user, &amount);
            prop_assert!(client.balance(&user) >= 0);
        }));
    }
}
```

---

## Dual-Perspective Verification (MANDATORY)

**Phase 1 -- ATTACKER**: Complete call sequence? Contracts to deploy? Profit in stroops? Compose multiple `invoke_contract` calls? Which `require_auth` is missing/bypassable?

**Phase 2 -- DEFENDER**: What `require_auth` prevents this? What storage key uniqueness ensures correct targeting? What external contract validation blocks substitution? Why safe by design?

**Phase 3 -- VERDICT**: Which argument won?

---

## Realistic Parameter Validation

Substitute ACTUAL contract constants. Apply Rule 10: worst realistic operational state, not current snapshot.

```
State: 'With real constants [fee_bps=X, precision=7_decimals, tvl=Z] at worst-state
[max_users, min_balance], bug triggers when [condition]'
OR: 'With real constants, bug does NOT trigger because [reason]'
```

**Stellar-specific constants**: XLM = 10,000,000 stroops (7 decimals) | Base reserve = 0.5 XLM (5,000,000 stroops) | Max TTL = 3,110,400 ledgers (~1yr at 5s) | Default min persistent TTL = 120 ledgers (~10min)

---

## Anti-Downgrade Guard (MANDATORY for VS/BLIND findings)

Apply Rule 13's 5-question test BEFORE downgrading severity or marking FALSE_POSITIVE:
1. **Who is harmed** by this design gap?
2. **Can affected users avoid** the harm?
3. **Is the gap documented** in protocol docs?
4. **Could the protocol achieve the same goal** without this gap?
5. **Does the function fulfill its stated purpose completely?**

**HARD RULE**: Contract A has protection X but Contract B lacks it for same user action -> defense parity gap, NOT "by design". Minimum severity: Medium.

---

## New Observations (MANDATORY)

If during verification you discover a NEW bug not covered by any hypothesis:
- [VER-NEW-1]: {title} -- {contract:function} -- {brief description}

---

## Error Trace Output (MANDATORY for CONTESTED/FALSE_POSITIVE)

- **Failure Type**: AUTH_REQUIRED / CONTRACT_TRAP / ARITHMETIC_OVERFLOW / STORAGE_MISSING / UNEXPECTED_STATE
- **Location**: {contract}:{function}:{approximate line}
- **Error Code**: {Soroban host error, e.g., `WasmVm(InvalidAction)`, `Auth(NotAuthorized)`}
- **State at Failure**: {key storage values}
- **Investigation Question**: {What would resolve this}

---

### Shared External Precedent Boundary

Read `~/.claude/rules/precedent-evidence-policy.md`.
Do not query vulnerability databases, WebSearch, or fresh RAG before or during
PoC adjudication. Seal the code-derived hypothesis, plan, and executed result
without historical anchoring. Centralized precedent can only create additive
test ideas in a separate post-plan phase; it is never verifier evidence and
cannot support a negative verdict, severity, proof, demotion, or report claim.

---

## Chain Hypothesis PoC Requirements

Chain hypotheses receive PRIORITY verification. Test the COMPLETE sequence: (1) execute enabler action, (2) assert postcondition created via `env.as_contract()` storage read, (3) execute previously-blocked exploit, (4) assert combined impact exceeds either finding alone. Use standard `Env::default()` + `mock_all_auths()` + `env.register()` setup.

---

## Interpreting Results

### Test PASSES -> Bug CONFIRMED

### Test FAILS -> Check Why

| Failure | Meaning | Action |
|---------|---------|--------|
| Auth error (`NotAuthorized`) | `require_auth` IS present | Re-examine hypothesis |
| Contract trap / WasmVm error | Logic assertion failed | Check if assertion is the bug or the fix |
| Arithmetic panic | Overflow protection present | Check if complete or partial |
| Storage `unwrap()` panic | Entry does not exist | Fix test setup |
| Wrong balance | Setup amounts incorrect | Verify stroops (7 decimals for XLM) |

---

## Iteration Protocol

**Attempt 1**: Direct implementation from hypothesis.
**Attempt 2**: Adjust parameters (amounts, ledger state, call ordering).
**Attempt 3**: Re-examine assumptions (auth mocking, storage keys, stroop vs XLM).
**Attempt 4**: Verify function signatures in source -- do NOT assume Solana/EVM shapes.
**Attempt 5**: Re-read anti-hallucination rules -- confirm correct Soroban testutils API.
**After 5 attempts**: FALSE_POSITIVE with documented reasoning.

---

## Insufficient Evidence (HALT CONDITIONS)

Before marking REFUTED, check ALL boxes:
- [ ] External contract behavior verified against PRODUCTION (not mock)
- [ ] Attack path checked on ALL public functions accessing same storage
- [ ] Profit calculated with attacker HOLDING tokens (not just calling)
- [ ] Missing precondition documented (STATE / ACCESS / TIMING / EXTERNAL / BALANCE)
- [ ] Searched other findings for matching postconditions (chain integration)
- [ ] Storage key derivation verified against actual DataKey enum
- [ ] `require_auth` calls verified by reading source (not assumed)
- [ ] TTL of relevant storage entries verified (Temporary may have expired)

### Evidence That Does NOT Count
- "Mock external contract shows X" -- mocks are not production
- "Function is called with `invoke_contract`" -- does not bypass `require_auth`
- "Attacker loses by sending tokens" -- may profit via position held elsewhere
- "Function is `pub(crate)`" -- may be reachable via cross-contract `invoke_contract`
- "Requires admin" -- admin may be compromised EOA or malicious upgrade
- "Storage key cannot collide" -- verify actual `DataKey` enum

---

## Output Format

### CONFIRMED
```markdown
## Verdict: CONFIRMED
### Bug Mechanism Verified
{2-3 sentences on what cargo test proves}
### Test Code
{Full Rust test using soroban-sdk testutils}
### Test Output
{Assertions and values from `cargo test -- --nocapture`}
### Key Evidence
| Metric | Value |
|--------|-------|
| Before / After / Expected / Difference | {stroops} |
### Evidence Audit
| Claim | Evidence Source | Tag | Valid for REFUTED? |
### Severity: {LEVEL}
{1-2 sentence justification}
### Suggested Fix
{diff block + Fix scope + Verified: YES/NO}
```

### FALSE_POSITIVE
```markdown
## Verdict: FALSE_POSITIVE
### Attempts Made
**Attempt 1-N:** Approach, Result (error type/code), Learning
### Evidence Audit
| Claim | Evidence Source | Tag | Valid for REFUTED? |
### Why It Is Not a Bug
{2-3 sentences}
### Error Trace
{Failure Type, Location, Error Code, State at Failure, Investigation Question}
```

### CONTESTED
```markdown
## Verdict: CONTESTED
### Evidence Status
| Checkpoint | Status | Details |
|------------|--------|---------|
| External contract verified against PRODUCTION | YES/NO | |
| All public function paths checked | YES/NO | |
| Auth flow completeness confirmed | YES/NO | |
| Storage TTL verified | YES/NO | |
### Evidence Audit
| Claim | Evidence Source | Tag | Valid for REFUTED? |
### Why This Cannot Be REFUTED
{What evidence is missing}
### Escalation Required
- [ ] Fetch production WASM/state for {external dep}
- [ ] Verify storage keys match DataKey enum in production
- [ ] Check additional function paths: {list}
### Error Trace
{as above}
```
