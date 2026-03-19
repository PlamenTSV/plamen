---
name: "token-flow-tracing"
description: "Trigger Pattern BALANCE_DEPENDENT flag (required) - Inject Into Depth-token-flow, breadth agents"
---

# TOKEN_FLOW_TRACING Skill

> **Trigger Pattern**: BALANCE_DEPENDENT flag (required)
> **Inject Into**: Depth-token-flow, breadth agents
> **Purpose**: Trace all token flows through Aptos Move protocols using FungibleAsset and Coin<T> models, identifying accounting desync, unsolicited deposit vectors, type confusion, and dispatchable hook side effects

For every token the protocol handles:

## 1. Asset Inventory

Enumerate ALL asset types the protocol handles:

| Asset | Model | Type Parameter / Metadata | Decimals | Entry Modules | Exit Modules |
|-------|-------|--------------------------|----------|---------------|-------------|
| {name} | Coin<T> / FungibleAsset | {CoinType or metadata Object} | {decimals} | {list} | {list} |

**Aptos dual token model**:
- **Legacy Coin<T>**: Uses `CoinStore<T>` resource at user address. Type parameter `T` identifies the coin.
- **FungibleAsset (FA)**: Uses `FungibleStore` objects. `Metadata` object identifies the asset type.
- **Paired assets**: Some tokens exist as both Coin<T> and FA simultaneously (APT is the primary example). Check if protocol handles both representations correctly.
- **Migration tokens**: Tokens migrated from Coin to FA model may have both interfaces active.

## 2. Token Entry Points

Where can tokens enter the protocol?

| Entry Path | Function | Asset Model | Accounting Updated? | Access Control |
|------------|----------|-------------|--------------------|--------------|
| Standard deposit | {deposit_fn} | {Coin/FA} | YES/NO | {who can call} |
| `primary_fungible_store::deposit()` | External | FA | NO (protocol unaware) | Permissionless |
| `coin::deposit<T>()` | External | Coin<T> | NO (protocol unaware) | Permissionless (if CoinStore registered) |
| Direct `fungible_asset::deposit()` | Via store ref | FA | NO (protocol unaware) | Requires FungibleStore reference |
| `move_to<T>()` | Internal | Resource | {depends} | Module only |
| Side-effect receipts | External call returns | {varies} | {depends} | {depends} |

**Red flags**:
- Protocol holds a FungibleStore whose reference is obtainable by external callers
- Protocol has registered CoinStore<T> making it a valid deposit target
- Protocol uses `object::generate_signer()` or `object::generate_extend_ref()` which could allow external deposits

## 3. Token Exit Points

Where can tokens leave the protocol?

| Exit Path | Function | Asset Model | Accounting Updated? | Access Control |
|-----------|----------|-------------|--------------------|--------------|
| Standard withdraw | {withdraw_fn} | {Coin/FA} | YES/NO | {who can call} |
| `primary_fungible_store::withdraw()` | Via signer | FA | {depends} | Requires signer capability |
| `coin::withdraw<T>()` | Via signer | Coin<T> | {depends} | Requires signer |
| `fungible_asset::withdraw()` | Via store ref | FA | {depends} | Requires store `&mut` ref or TransferRef |
| Fee distribution | {fee_fn} | {varies} | YES/NO | {access} |
| Emergency withdraw | {emergency_fn} | {varies} | YES/NO | {admin} |

For each exit: does the tracked balance decrease BEFORE or AFTER the actual transfer?
For each transfer call: can the source account be underfunded at execution time? (funds deployed externally, locked, or lent out → transfer reverts)

### 3b. Self-Transfer Accounting
For each transfer function: can the sender and recipient be the same account/address?
If YES: does a self-transfer update accounting state (fees credited, rewards claimed, snapshots updated, share ratios changed) without net token movement? Flag as FINDING.

## 4. Balance Tracking Analysis

For each asset type:

| Asset | Internal Tracking Variable | On-Chain Balance Query | Can Desync? | Desync Vector |
|-------|---------------------------|----------------------|-------------|---------------|
| {name} | {e.g., total_deposited in resource} | `fungible_asset::balance(store)` or `coin::balance<T>(addr)` | YES/NO | {if YES: how} |

**Critical question**: Does the protocol use internal accounting or direct on-chain balance queries?

- **Internal accounting**: Protocol maintains its own `total_deposited` / `total_assets` resource -> SAFE from donation attacks IF consistently updated
- **Direct balance query**: Protocol reads `fungible_asset::balance()` or `coin::balance<T>()` directly -> **DONATION ATTACK VECTOR** -- attacker can inflate balance without protocol awareness

**Red flags**:
- Exchange rate calculations using `fungible_asset::balance(store)` directly
- No reconciliation function to handle accounting discrepancies
- Accounting variables updated BEFORE token transfer completes (not relevant in Move's linear type system, but check for resource mutation ordering)

## 5. Unsolicited Deposit Analysis

Can tokens be deposited to the protocol without calling its deposit function?

If **YES** (most cases on Aptos):

### 5a. Unsolicited Deposit Vectors

| Vector | Asset Model | Protocol Aware? | Impact |
|--------|-------------|----------------|--------|
| `primary_fungible_store::deposit(protocol_addr, fa)` | FA | NO | {impact} |
| `coin::deposit<T>(protocol_addr, coin)` | Coin<T> | NO | {impact} |
| Direct transfer to object-owned store | FA | NO | {impact} |

### 5b. Unsolicited Transfer Matrix (All Token Types) -- R11 Five Dimensions

For EVERY external token type the protocol holds, queries, or receives as side effects:

| Token Type | Can Deposit Unsolicited? | Accounting Distortion? | Share Inflation? | Threshold Manipulation? | Reward Dilution? | Fee Calculation Impact? |
|------------|------------------------|----------------------|-----------------|----------------------|-----------------|----------------------|
| {token_a} | YES/NO | YES/NO | YES/NO | YES/NO | YES/NO | YES/NO |

**RULE**: If ANY token type is unsolicited-depositable AND affects state -> analyze each consequence:
- **Accounting distortion**: Does tracked vs actual balance diverge?
- **Share inflation**: Does unsolicited deposit inflate share price (more assets per share)?
- **Threshold manipulation**: Can unsolicited deposits push protocol past thresholds?
- **Reward dilution**: Do unsolicited deposits dilute rewards for existing participants?
- **Fee calculation**: Do fees computed on balance include unsolicited deposits?

If **NO**:
- Why not? (No CoinStore registered? Store not publicly accessible? Custom deposit hooks reject?)
- Is the protection reliable? (Can it be bypassed via object manipulation?)

## 6. Token Type Confusion

Can the wrong asset type be used where another is expected?

| Check | Location | Status | Impact |
|-------|----------|--------|--------|
| FungibleAsset metadata validated on deposit? | {fn} | YES/NO | Wrong FA type accepted |
| Coin<T> type parameter constrains to expected type? | {fn} | YES/NO (compile-time) | N/A for Coin (type-safe) |
| Paired Coin/FA confusion? | {fn} | YES/NO | Same asset counted twice |
| Metadata address hardcoded or validated? | {fn} | {which} | Spoofed metadata |

**Aptos-specific type confusion vectors**:
- FungibleAsset metadata is an Object address -- if not validated, attacker-created FA with fake metadata could be deposited
- Coin<T> is type-safe at compile time (T must match), but FungibleAsset is identified by metadata Object at runtime
- If protocol accepts both Coin<T> AND FungibleAsset for the same underlying token, can the same deposit be counted under both models?

## 7. Dispatchable Hook Impact

If any token in scope uses the Aptos FungibleAsset dispatchable hooks (`DispatchFunctionStore`):

| Token | Hook Type | Hook Function | Side Effect | Protocol Handles? |
|-------|-----------|--------------|-------------|-------------------|
| {token} | deposit | {module::fn} | {effect} | YES/NO |
| {token} | withdraw | {module::fn} | {effect} | YES/NO |
| {token} | derived_balance | {module::fn} | {effect} | YES/NO |

**Analysis questions**:
- Can deposit hooks cause reentrancy-like behavior? (hook calls back into protocol during deposit)
- Can withdraw hooks block withdrawals? (hook aborts on certain conditions)
- Can derived_balance hooks return manipulated values? (custom balance reporting)
- Does the protocol check `is_dispatchable()` before interacting with tokens?

## 8. Zero-Value Operations

What happens with zero-amount deposits/withdrawals?

| Operation | Zero Amount Behavior | Accounting Impact | Shares Issued/Burned? |
|-----------|---------------------|-------------------|----------------------|
| deposit(0) | {aborts/succeeds} | {state change?} | {0 shares / abort?} |
| withdraw(0) | {aborts/succeeds} | {state change?} | {0 shares burned?} |
| transfer(0) | {aborts/succeeds} | {state change?} | N/A |

**Red flags**:
- Zero-amount deposit succeeds and issues shares (division by zero in rate calculation)
- Zero-amount withdraw triggers reward claims or state updates without actual token movement
- Zero-amount operations bypass minimum balance checks

## 9. Cross-Token Interactions

For protocols handling multiple token types:

| Token A | Token B | Interaction | Can A Affect B? | Impact |
|---------|---------|-------------|----------------|--------|
| {tokenA} | {tokenB} | {rate dependency / collateral relationship / swap} | YES/NO | {impact} |

- Can operations on TokenA affect TokenB's accounting?
- Are there exchange rate dependencies between tokens?
- Can withdrawing TokenA affect availability of TokenB?
- If protocol handles both Coin<T> and FA representations of same asset, are operations on one reflected in the other?

## 10. Token Flow Checklist

For each token identified:

| Token | Entry Points | Exit Points | Tracking Var | Direct Balance Query Used? | Unsolicited Possible? |
|-------|--------------|-------------|--------------|---------------------------|----------------------|
| {name} | {list} | {list} | {var} | YES/NO | YES/NO |

## Instantiation Parameters
```
{CONTRACTS}           -- Move modules to analyze
{ASSET_TYPES}         -- FungibleAsset metadata and Coin<T> types in scope
{ENTRY_FUNCTIONS}     -- Functions where tokens enter the protocol
{EXIT_FUNCTIONS}      -- Functions where tokens leave the protocol
{BALANCE_VARS}        -- Internal balance tracking variables
{EXTERNAL_TOKENS}     -- External token types the protocol interacts with
```

## Finding Template

```markdown
**ID**: [TF-N]
**Severity**: [based on fund impact]
**Step Execution**: checkmark1,2,3,4,5,6,7,8,9,10 | x(reasons) | ?(uncertain)
**Rules Applied**: [R1:Y, R4:Y, R10:Y, R11:Y]
**Location**: module::function:LineN
**Title**: [Asset type] can enter/exit via [path] without [expected accounting update]
**Description**: [Trace the token flow and where it diverges from expected]
**Impact**: [What breaks: exchange rates, user balances, protocol insolvency]
```

## Output Schema

| Field | Required | Description |
|-------|----------|-------------|
| asset_inventory | yes | All asset types and their models |
| entry_points | yes | Token entry paths with accounting status |
| exit_points | yes | Token exit paths with accounting status |
| balance_tracking | yes | Internal vs on-chain balance analysis |
| unsolicited_vectors | yes | Unsolicited deposit analysis (R11 5 dimensions) |
| type_confusion | yes | Token type validation issues |
| finding | yes | CONFIRMED / REFUTED / CONTESTED |
| evidence | yes | Code locations with line numbers |
| step_execution | yes | Status for each step |

---

## Step Execution Checklist (MANDATORY)

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1. Asset Inventory | YES | Y/x/? | |
| 2. Token Entry Points | YES | Y/x/? | |
| 3. Token Exit Points | YES | Y/x/? | |
| 4. Balance Tracking Analysis | YES | Y/x/? | |
| 5. Unsolicited Deposit Analysis | YES | Y/x/? | |
| 5b. Unsolicited Transfer Matrix (All Types) | **YES** | Y/x/? | **MANDATORY** -- never skip (R11) |
| 6. Token Type Confusion | YES | Y/x/? | |
| 7. Dispatchable Hook Impact | IF dispatchable tokens | Y/x(N/A)/? | |
| 8. Zero-Value Operations | YES | Y/x/? | |
| 9. Cross-Token Interactions | IF multi-token | Y/x(N/A)/? | |
| 10. Token Flow Checklist | YES | Y/x/? | |

### Cross-Reference Markers

**After Section 5** (Unsolicited Deposit Analysis):
- IF unsolicited deposits possible -> **MUST complete Section 5b with ALL 5 R11 dimensions**
- IF FungibleAsset with dispatchable hooks -> **MUST complete Section 7**

**After Section 6** (Token Type Confusion):
- IF protocol handles both Coin<T> and FA for same underlying -> **MUST check double-counting in Section 9**
- Cross-reference with `ZERO_STATE_RETURN.md` for first-depositor amplification via unsolicited deposits

**After Section 7** (Dispatchable Hook Impact):
- IF hooks can abort -> trace all callers for uncaught abort impact
- IF hooks have side effects -> trace through to accounting consistency
