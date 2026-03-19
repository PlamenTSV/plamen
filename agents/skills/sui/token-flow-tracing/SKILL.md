---
name: "token-flow-tracing"
description: "Trigger Pattern BALANCE_DEPENDENT flag (required) - Inject Into Depth-token-flow, breadth agents"
---

# TOKEN_FLOW_TRACING Skill (Sui)

> **Trigger Pattern**: BALANCE_DEPENDENT flag (required)
> **Inject Into**: Depth-token-flow, breadth agents
> **Purpose**: Trace all Coin<T> and Balance<T> flows through Sui Move protocols to identify accounting desync, unsolicited deposit vectors, type confusion, and token lifecycle issues

For every token the protocol handles:

## 1. Asset Inventory

Enumerate ALL `Coin<T>` and `Balance<T>` types the protocol handles:

| Token Type | Representation | Location (module::struct field) | Owned or Shared? | Entry Functions | Exit Functions |
|------------|---------------|-------------------------------|-------------------|-----------------|----------------|
| {e.g., SUI} | Balance<SUI> | pool::Pool.balance | Shared object | deposit() | withdraw() |
| {e.g., USDC} | Coin<USDC> | (function parameter) | Owned (user) | swap_in() | swap_out() |

**Sui-specific representations**:
- `Coin<T>`: Owned object with `id: UID` and `balance: Balance<T>`. Has `key + store` abilities -- freely transferable to any address via `transfer::public_transfer`. This is the primary unsolicited transfer vector on Sui.
- `Balance<T>`: Value type with `store` ability only (no `key`). Stored inside other objects. Cannot exist as a standalone on-chain object. Must live inside a struct with `key`.
- `TreasuryCap<T>`: Capability to mint/burn. Must be tracked.
- Dynamic fields storing `Balance<T>`: Hidden balance storage -- check `dynamic_field::add/borrow/remove`.

## 2. Token Entry Points

Where can tokens enter the protocol?

| Entry Path | Function | Token Form | Accounting Update | Validated? |
|------------|----------|-----------|-------------------|------------|
| Standard deposit | {module::deposit} | Coin<T> parameter | {state variable updated} | YES/NO |
| PTB coin splitting | (PTB splits user coin) | Coin<T> from split | {same as above?} | N/A |
| Direct transfer | transfer::public_transfer | Coin<T> to address | NONE -- creates new owned object | NO |
| Balance merge | balance::join | Balance<T> | {state variable updated?} | YES/NO |
| Mint | coin::from_balance / coin::mint | TreasuryCap | {supply tracking} | YES/NO |
| Side-effect receipt | {external call returns coin} | Coin<T> | {handled?} | YES/NO |

**Sui-specific entry analysis**:
- `coin::into_balance(coin)` converts Coin<T> to Balance<T> -- does the protocol track this conversion?
- `coin::split(&mut coin, amount, ctx)` creates a new Coin<T> -- does the protocol validate the split amount?
- Can users pass zero-value coins? (`coin::zero<T>(ctx)`)

## 3. Token Exit Points

Where can tokens leave the protocol?

| Exit Path | Function | Token Form | Accounting Update | Authorized? |
|-----------|----------|-----------|-------------------|-------------|
| Standard withdraw | {module::withdraw} | Coin<T> returned | {state variable decremented} | {access check} |
| Transfer out | transfer::public_transfer | Coin<T> | {accounting updated?} | {access check} |
| Balance extraction | balance::split | Balance<T> | {state variable decremented?} | {access check} |
| Burn | coin::burn / balance::decrease_supply | TreasuryCap | {supply tracking} | {cap holder} |
| Fee distribution | {fee function} | Coin<T> or Balance<T> | {fee accounting} | {access check} |
| Emergency withdraw | {emergency function} | Coin<T> | {does it clear ALL state?} | {admin cap?} |

For each exit: does the tracked balance decrease BEFORE or AFTER the actual balance extraction?
For each transfer/withdrawal: can the source be underfunded at execution time? (funds deployed externally, locked, or lent out → transfer aborts)
Check for:
- `balance::split` before state update -> can the function abort between split and update?
- State update before `balance::split` -> can state be inconsistent if split aborts?

### 3b. Self-Transfer Accounting
For each transfer function: can the sender and recipient be the same address/object?
If YES: does a self-transfer update accounting state (fees credited, rewards claimed, snapshots updated, share ratios changed) without net token movement? Flag as FINDING.

## 4. Balance Tracking and Desync Analysis

For each token in the protocol:

| Token | Internal Tracking Variable | Actual Balance Source | Can They Desync? | Desync Vector |
|-------|---------------------------|---------------------|-----------------|---------------|
| {token} | {e.g., pool.total_deposited} | balance::value(&pool.balance) | YES/NO | {how} |

**Red flags**:
- Exchange rate calculations using `balance::value()` directly instead of tracked internal variable
- No reconciliation mechanism between tracked and actual balance
- Accounting variables updated in a different function than the balance transfer
- `balance::join(&mut pool.balance, deposit_balance)` without incrementing tracked counter

**Sui-specific desync vectors**:
- `balance::join` into a shared object's Balance<T> without updating the tracking variable
- Dynamic field operations that add/remove Balance<T> without pool-level accounting
- Multiple shared objects holding the same token type with aggregate accounting errors

## 5. Unsolicited Deposit Analysis

Can tokens be added to the protocol's balance without going through deposit logic?

**Sui object model considerations**:
- **Owned objects**: Only the owner can access. Sending `Coin<T>` via `transfer::public_transfer` to a shared object's address creates a NEW owned object at that address -- it does NOT add to the shared object's `Balance<T>`. The protocol would need to explicitly receive and merge it.
- **Shared objects**: Anyone can call functions on shared objects, but cannot directly modify their `Balance<T>` fields without going through the module's public API.
- **However**: If the module exposes a public function that accepts `Coin<T>` and calls `balance::join` without proper accounting, this IS a donation vector.

| Donation Path | Possible? | Changes Protocol Balance? | Breaks Accounting? | Impact |
|---------------|-----------|--------------------------|-------------------|--------|
| transfer::public_transfer to pool address | YES (creates owned obj) | NO (not auto-merged) | NO (unless protocol sweeps) | {analysis} |
| Public function accepting Coin<T> without accounting | {YES/NO} | YES | YES | {analysis} |
| Dynamic field injection | {YES/NO -- needs module API} | {YES/NO} | {YES/NO} | {analysis} |
| Reward/fee distribution to protocol address | {YES/NO} | {YES/NO} | {YES/NO} | {analysis} |

### 5b. Unsolicited Transfer Matrix (All Token Types)

For EVERY external token type the protocol holds, queries, or receives as side effects -- not just the protocol's primary token:

| Token Type | Can Be Sent to Protocol? | Changes Protocol Accounting? | Blocks Operations? | Triggers Side Effects? |
|------------|--------------------------|-----------------------------|--------------------|----------------------|
| {token_a} | YES/NO | YES/NO | YES/NO | YES/NO |

**RULE**: If ANY token type can enter the protocol's balance AND affects state -> analyze each consequence:
- Accounting impact: Does tracked vs actual balance diverge?
- Iteration impact: Does the protocol iterate over sources of this token? (gas DoS vector via object count)
- Operation blocking: Does non-zero balance of this token prevent admin operations?
- Side effect chain: Does receiving this token trigger further side effects?

## 6. Token Type Confusion

Can the wrong `Coin<T>` type be passed to protocol functions?

| Function | Expected Type Parameter | Validated? | What if Wrong Type? |
|----------|------------------------|-----------|---------------------|
| {function} | Coin<USDC> | {by Move type system / runtime check} | {impact} |

**Sui Move type safety**: Move's type system provides strong static guarantees -- `Coin<USDC>` and `Coin<SUI>` are different types at compile time. However:
- Generic functions `fun deposit<T>(coin: Coin<T>)` accept ANY `Coin<T>` -- is `T` validated?
- Does the protocol check `T` against an allowed list? (e.g., `assert!(type_name::get<T>() == allowed_type)`)
- Can an attacker create a custom token type and pass `Coin<ATTACKER_TOKEN>` to a generic function?
- For pools with multiple token types: can the type parameters be swapped? (e.g., `Pool<A, B>` called with `Coin<B>` where `Coin<A>` expected)

## 7. Coin Splitting and Merging

Analyze `coin::split()` and `coin::join()` / `balance::split()` and `balance::join()` operations:

| Operation | Location | Amount Source | Validated? | Edge Cases |
|-----------|----------|-------------|-----------|------------|
| coin::split(&mut coin, amount, ctx) | {location} | {user input / computed} | {amount <= coin.value?} | {amount = 0? amount = full value?} |
| coin::join(&mut coin_a, coin_b) | {location} | {coin_b.value} | {overflow check?} | {coin_b is zero?} |
| balance::split(&mut bal, amount) | {location} | {computed} | {amount <= bal.value?} | {amount = 0?} |
| balance::join(&mut bal_a, bal_b) | {location} | {bal_b.value} | {overflow check?} | {bal_b is zero?} |

**Check**:
- Off-by-one errors in split amounts
- Dust remaining after splits (tiny amounts that cannot be withdrawn)
- Zero-value splits: `coin::split(&mut coin, 0, ctx)` creates a zero-value coin -- does the protocol handle this?
- Full-value splits: splitting the entire balance leaves a zero-value coin/balance in place

## 8. Zero-Value Operations

What happens with zero-value tokens?

| Operation | Zero Input Behavior | Impact |
|-----------|-------------------|--------|
| deposit(coin::zero<T>()) | {aborts / succeeds / mints zero shares} | {accounting impact} |
| withdraw(0) | {aborts / succeeds / burns zero shares} | {accounting impact} |
| swap(coin::zero<T>()) | {aborts / succeeds} | {state change without value?} |
| claim_rewards() when rewards = 0 | {aborts / succeeds} | {side effects?} |

**Check**: Can zero-value operations be used to:
- Trigger state changes without economic commitment?
- Reset cooldown timers?
- Increment counters or advance epochs?
- Create empty objects that consume storage?

## 9. Cross-Token Interactions

For protocols with multiple token types:

| Interaction | Token A | Token B | Dependency | Impact |
|-------------|---------|---------|-----------|--------|
| Exchange rate | {A type} | {B type} | {A balance affects B's rate?} | {if A manipulated, B price changes?} |
| Collateral/debt | {collateral type} | {debt type} | {collateral value gates borrowing} | {if collateral inflated, excess borrowing} |
| LP composition | {A type} | {B type} | {ratio determines share value} | {imbalance vector} |

- Can operations on Token A affect Token B's accounting?
- Are there exchange rate dependencies between tokens?
- Can withdrawing Token A affect availability of Token B?

## Finding Template

```markdown
**ID**: [TF-N]
**Severity**: [based on fund impact]
**Step Execution**: check1,2,3,4,5,6,7,8,9 | x(reasons) | ?(uncertain)
**Rules Applied**: [R1:check, R11:check, R4:check, R10:check]
**Location**: module::function:LineN
**Title**: [Token type] can enter/exit via [path] without [expected accounting update]
**Description**: [Trace the token flow and where it diverges from expected]
**Impact**: [What breaks: exchange rates, user balances, protocol insolvency]
```

## Instantiation Parameters
```
{CONTRACTS}           -- Move modules to analyze
{TOKEN_TYPES}         -- Coin<T>/Balance<T> types handled
{SHARED_OBJECTS}      -- Shared objects holding balances
{ENTRY_FUNCTIONS}     -- Token deposit/entry functions
{EXIT_FUNCTIONS}      -- Token withdraw/exit functions
{GENERIC_FUNCTIONS}   -- Functions with type parameter <T>
```

## Output Schema
| Field | Required | Description |
|-------|----------|-------------|
| asset_inventory | yes | All Coin<T> and Balance<T> types |
| entry_points | yes | All token entry paths |
| exit_points | yes | All token exit paths |
| balance_tracking | yes | Internal vs actual balance analysis |
| unsolicited_analysis | yes | Donation/unsolicited deposit vectors |
| type_confusion | yes | Type parameter validation |
| finding | yes | CONFIRMED / REFUTED / CONTESTED |
| evidence | yes | Code locations with line numbers |
| step_execution | yes | Status for each step |

---

## Step Execution Checklist (MANDATORY)

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1. Asset Inventory | YES | check/x/? | |
| 2. Token Entry Points | YES | check/x/? | |
| 3. Token Exit Points | YES | check/x/? | |
| 4. Balance Tracking and Desync | YES | check/x/? | |
| 5. Unsolicited Deposit Analysis | YES | check/x/? | |
| 5b. Unsolicited Transfer Matrix (All Types) | **YES** | check/x/? | **MANDATORY** -- never skip |
| 6. Token Type Confusion | YES | check/x/? | |
| 7. Coin Splitting and Merging | YES | check/x/? | |
| 8. Zero-Value Operations | YES | check/x/? | |
| 9. Cross-Token Interactions | IF multi-token | check/x(N/A)/? | |

### Cross-Reference Markers

**After Section 5** (Unsolicited Deposit Analysis):
- IF donation vectors found -> **MUST check impact on exchange rates in Section 4**
- IF protocol has generic functions -> **MUST complete Section 6**

**After Section 7** (Coin Splitting and Merging):
- IF dust amounts possible -> **MUST check zero-value impact in Section 8**
- Cross-reference with ZERO_STATE_RETURN for residual balance implications

**After Section 8** (Zero-Value Operations):
- IF zero-value operations cause state changes -> FINDING (minimum Low)
- Document: "Zero-value [operation] triggers [state change] without economic commitment"
