# Generic Security Rules - Aptos Move

> **Usage**: Analysis agents and depth agents reference these rules during Aptos Move module analysis.
> These rules cover ALL Aptos Move modules regardless of type. Rules R1-R17 are adapted from EVM equivalents. Rules MR1-MR5 are shared Move rules. Rules AR1-AR4 are Aptos-specific.

---

## Rule R1: Module Call Return and State Validation (adapted from EVM R1)

**Pattern**: Any call to external module functions that returns values or modifies global state
**Check**: Does the ACTUAL return type/value match what the calling module EXPECTS? Is global state consistent after the call?

| Mismatch Type | Example | Impact |
|---------------|---------|--------|
| `Coin<T>` type confusion | Function expects `Coin<AptosCoin>`, receives `Coin<FakeToken>` via generic | Wrong token processed, accounting corruption |
| FungibleAsset metadata mismatch | Module reads metadata Object expecting USDC FA, passed arbitrary FA metadata | Incorrect decimals, wrong asset valued |
| `borrow_global` type mismatch | Generic `T` resolved to unexpected struct - `borrow_global<T>(addr)` returns attacker-controlled data | State corruption, authorization bypass |
| Phantom type parameter abuse | `Pool<phantom CoinA, phantom CoinB>` instantiated with swapped types | Pair confusion, LP token minting for wrong pool |
| Object type confusion | `Object<T>` passed where `T` is not validated against actual stored type | Wrong resource read, capability escalation |
| Legacy Coin vs FungibleAsset | Module expects `Coin<T>`, receives FA migration wrapper (or vice versa) | Transfer failures, missing hook handling |
| Decimal/exponent mismatch | Token with 6 decimals treated as 8 | Over/undervalued by 10^N |

**Aptos-specific**: Move's type system prevents most type mismatches at compile time. However, generic functions (`fun process<T>(coin: Coin<T>)`) accept ANY type satisfying ability constraints. If business logic requires a SPECIFIC coin type, runtime validation via `type_info` or a whitelist registry is needed.

**Action**: For every cross-module call returning resources or values: (1) trace the concrete type that the external module ACTUALLY returns, (2) verify generic type parameters are constrained and cannot be substituted with adversarial types, (3) for `Object<T>` parameters - verify `T` matches the object's stored resource type, (4) for FungibleAsset - verify metadata object matches expected asset, (5) state accessed after external calls reflects any mutations made by those calls.

---

## Rule R2: Function Preconditions Are Griefable (adapted from EVM R2)

**Pattern**: Any `public entry` function or `public` function with preconditions based on externally-manipulable state
**Check**: Can external actors manipulate state to make the precondition fail or succeed at the wrong time?

```move
public entry fun keeper_action(keeper: &signer) {
    let balance = coin::balance<APT>(signer::address_of(keeper));
    assert!(balance > THRESHOLD, E_INSUFFICIENT); // ANYONE CAN DRAIN TO GRIEF
    // ...
}
```

This includes:
- Keeper/operator functions with balance-dependent preconditions (`coin::balance<T>(addr) > threshold`)
- Permissionless entry functions with oracle-dependent preconditions
- Functions reading `FungibleStore` balances that can be donated to
- Functions with `exists<T>(addr)` preconditions where `T` can be created externally

**Aptos-specific vectors**:
- **Resource creation front-running**: Attacker calls `move_to` to create a resource at an address before legitimate initialization, blocking `move_to` (which aborts if resource already exists)
- **FungibleStore donation**: Anyone can deposit FungibleAsset via `primary_fungible_store::deposit` to inflate a store's balance without recipient consent
- **Coin donation**: `aptos_account::transfer_coins<T>()` or `coin::deposit()` can send coins to any address with a registered `CoinStore<T>`
- **Object creation front-running**: Attacker creates named objects at predictable addresses (`object::create_named_object`) before the protocol
- **APT direct transfer**: `aptos_account::transfer()` sends APT to any address, creating the account if needed

**Direction 2 - Admin action impacts on user functions**: For every admin setter that modifies a parameter stored in global storage and used in user-facing function preconditions:
1. Can an admin parameter change make a user-facing function behave unexpectedly? (e.g., setting `max_deviation = 0` disables oracle bounds, setting `cooldown = 0` removes timing protection)
2. Does the admin change retroactively affect users in active positions? (e.g., changing withdrawal delay while users have pending withdrawals)

**Action**: For every function with a precondition, identify whether the precondition state can be manipulated by: (1) direct user action (deposit/withdraw/transfer), (2) transaction composition in the same script, (3) Coin/FungibleAsset/APT donation (unsolicited transfers), (4) resource or object creation front-running.

---

## Rule R3: Transfer Side Effects (adapted from EVM R3)

**Pattern**: Any token transfer operation (`Coin<T>` or `FungibleAsset`)
**Check**: Does the transfer trigger side effects?

| Token Type | Side Effect | Check |
|-----------|------------|-------|
| Legacy `Coin<T>` | `CoinStore` deposit/withdraw events emitted; NO hooks | Event consumers affected? No reentrancy risk. |
| Standard FungibleAsset (no hooks) | Events emitted; NO hooks | Verify no dispatchable hooks registered |
| FungibleAsset with `DepositHandler` | Custom `deposit` hook executes on every deposit | Reentrancy risk, state changes, abort risk |
| FungibleAsset with `WithdrawHandler` | Custom `withdraw` hook executes on every withdrawal | Reentrancy risk, accounting changes, abort risk |
| FungibleAsset with `TransferHandler` | Custom `transfer` hook executes on every transfer | Reentrancy risk, CAN introduce arbitrary code execution |
| FungibleAsset with `derived_balance` | Custom balance function overrides balance query | Manipulated accounting, stale computation |
| Object transfer | Object ownership changes | Capability migration, permission changes |
| `aptos_account::transfer` | Creates account if not exists, registers `CoinStore<AptosCoin>` | Gas cost, unexpected resource creation |

**Mandatory check**: For every token the protocol handles:
- [ ] Is it legacy `Coin<T>` or `FungibleAsset`?
- [ ] If `FungibleAsset`: are dispatchable hooks registered (`DepositHandler`, `WithdrawHandler`, `TransferHandler`, `derived_balance`)?
- [ ] If dispatchable hooks exist: can they reenter the calling module?
- [ ] If dispatchable hooks exist: can they abort, causing DoS?
- [ ] Does the operation emit events consumed by off-chain systems?
- [ ] For Object-based tokens: does ownership transfer change any capabilities?

**Output requirement** (in attack_surface.md Token Flow Matrix):
| Token | Type (Coin/FA) | Dispatchable Hooks? | On-Transfer Side Effect | Verified? |
|-------|---------------|--------------------|-----------------------|-----------|

---

## Rule R4: Uncertainty Handling (CONTESTED + Adversarial Assumption)

**CONTESTED is a TRIGGER, not a TERMINAL state.**

When marking any finding as CONTESTED:
1. **Enumerate**: List ALL plausible external behaviors (Scenario A, B, C...)
2. **Assess**: For each scenario, what's the severity IF that behavior is true?
3. **Escalate**: If ANY scenario results in HIGH/CRITICAL, flag for production verification
4. **Default**: Use WORST-CASE severity until production behavior is verified

**For any external module behavior that is UNKNOWN, assume adversarial:**
1. Assume the behavior that causes MAXIMUM harm
2. Produce an impact trace for the adversarial case
3. Mark as CONDITIONAL until production verified
4. Cannot REFUTE based on mock behavior or documentation alone

**Aptos-specific uncertainty sources**:
- **Upgradeable modules**: Modules with `can_change_* = true` in `PackageMetadata` may change behavior after audit. Check upgrade policy via `aptos_framework::code`.
- **Dispatchable function hooks**: FungibleAsset hooks in external modules may change if the hook module is upgradeable
- **Generic type parameters**: Unknown concrete types supplied at call time - behavior depends on what type the caller provides
- **Object references**: `Object<T>` references may point to objects controlled by external modules
- **Resource account behavior**: ResourceAccount with `SignerCapability` - who holds the capability? Can the holder change?

**Workflow integration**:
- CONTESTED findings receive same verification priority as HIGH findings
- CONTESTED findings trigger production verification checkpoint
- Cannot downgrade CONTESTED to REFUTED without production evidence

---

## Rule R5: Combinatorial Impact Analysis (adapted from EVM R5)

**For protocols managing N similar entities, analyze cumulative impact.**

When a protocol manages multiple vaults, pools, markets, or user positions:

**Mandatory analysis**:
1. **Single-entity impact**: What's the impact on ONE entity?
2. **N-entity cumulative**: What's N * single_impact? (check if capped by constraints)
3. **Time-compound**: What's N * impact * T? (check for accumulation over time)

**Aptos-specific considerations**:
- **`SimpleMap` is O(N) for lookups**: Large `SimpleMap` instances cause gas exhaustion. If N entities stored in SimpleMap, gas scales linearly.
- **`Table`/`SmartTable` are O(1) amortized**: But have no built-in iteration. Modules iterating via a parallel `SmartVector` or `vector` of keys are gas-bounded by the key collection size.
- **Max transaction gas**: Aptos transactions have configurable gas limits. Batch operations across N entities may exceed gas budget.
- **Event emission volume**: N entities each emitting events can create indexer lag or off-chain processing failures.
- **Vector iteration**: `vector::for_each` over large vectors can exceed `max_gas` per transaction.

**Thresholds**:
- If N >= 10 AND cumulative impact > $1,000, analyze further
- If N * dust > withdrawal_threshold, flag as potential griefing vector
- If batch operation over N entities approaches max gas, flag as DoS vector

---

## Rule R6: Semi-Trusted Role Bidirectional Analysis

**For any automated or privileged role, analyze BOTH directions.**

**Direction 1**: How can ROLE harm USERS?
- Timing attacks (front-running user transactions within block ordering; Aptos has ~1s block time)
- Parameter manipulation (choosing worst values within setter bounds)
- Omission (failing to execute when needed, e.g., not updating oracle prices)
- Capability abuse (using `MintRef`, `BurnRef`, `TransferRef` adversarially within stated permissions)

**Direction 2**: How can USERS exploit ROLE?
- Front-run predictable keeper/operator actions
- Grief preconditions to block keeper operations
- Force suboptimal keeper decisions via state manipulation
- Drain keeper's gas budget via unnecessary trigger conditions

**Both directions are equally important. Do NOT stop at Direction 1.**

**Aptos-specific roles to audit**:
- Module deployer (upgrade authority - can change module code)
- Capability holders (`MintRef`, `BurnRef`, `TransferRef`, `ExtendRef`)
- `SignerCapability` holders (can sign as resource account)
- `friend` module authors (access to `public(friend)` functions)
- Object owners (can transfer objects, manage object resources if authorized)

---

## Rule R7: Donation-Based DoS via Threshold Manipulation (adapted from EVM R7)

**Pattern**: Protocol has thresholds that determine operational capability
**Check**: Can donations manipulate thresholds to block operations?

**Aptos-specific attack vectors**:
1. **APT transfer**: Anyone can send APT to any address via `aptos_account::transfer()` - creates account if needed
2. **Coin<T> transfer**: Anyone can send `Coin<T>` to any address via `aptos_account::transfer_coins<T>()` or `coin::deposit()` if `CoinStore<T>` exists
3. **FungibleAsset deposit**: `primary_fungible_store::deposit()` deposits FA to any address, creating a store if needed - no recipient consent required
4. **Resource creation blocking**: `move_to` aborts if resource already exists at address - attacker creates resource first to block legitimate initialization
5. **Object creation front-running**: Attacker creates named objects at predictable addresses before the protocol
6. **Counter-based gate inflation**: For every counter-based gate (e.g., `count >= minimum`), check: can entries be added that increment the counter but contribute zero/negligible value to the guarded computation? If yes, the gate passes but the guarded computation produces a meaningless or manipulable result (e.g., TWAP accepting zero-weight snapshots to satisfy minimum count requirement).

**Action**: For every operational threshold, check if external donations or resource creation can manipulate it to cause denial of service. For every counter-based gate, check if zero-value entries can satisfy the count requirement while undermining the guarded computation's integrity.

---

## Rule R8: Cached Parameters in Multi-Step Operations (adapted from EVM R8)

**Pattern**: Operation spans multiple transactions with cached initial state stored in global resources
**Check**: Can parameters change between operation start and completion?

**Attack vectors**:
1. **Epoch/round staleness**: Cache epoch or round number at request time, governance changes parameters mid-operation
2. **Rate staleness**: Cache exchange rate at start, rate updates before claim completes
3. **Delay manipulation**: Cache delay value in a resource, delay changed by admin before execution
4. **External state staleness**: External module state (ownership, approval, delegation, module status) read and stored in one transaction, relied upon in a later transaction without re-verification. The external state may change between the two calls.

**Aptos-specific additions**:
- **Resource snapshot staleness**: A module reads `borrow_global<Config>(addr).rate` and stores the value in a user's pending operation resource. Between the request and claim transactions, `Config.rate` changes.
- **Object ownership staleness**: An `Object<T>` ownership is checked in transaction 1 and stored. Object is transferred by the owner between transactions.
- **Global storage mutation during execution**: A resource read via `borrow_global` at function start may be mutated by an external module call during the same function execution (if the external module has `borrow_global_mut` access to the same resource - only possible for resources under a different address or of a different type)
- **Module upgrade between steps**: If an external module is upgraded between transaction 1 and transaction 2 of a multi-step operation, its behavior may change entirely.

**Action**: For multi-step operations (request -> wait -> claim) AND for any function that stores a snapshot of external module state in global storage, verify all cached/stored state remains valid or is re-validated at each subsequent consumption point.

---

## Rule R9: Stranded Asset Severity Floor (adapted from EVM R9)

**Pattern**: Assets held by the protocol with no exit path after upgrade, migration, or state change
**Check**: Can ALL asset types the protocol holds be recovered?

**Aptos-specific stranding scenarios**:
- **Immutable module**: Module published with immutable upgrade policy (`can_change_* = false`) - if no withdrawal function exists, assets are permanently locked
- **Resource account without signer capability**: Assets in a resource account where `SignerCapability` is lost or never stored - no way to sign transactions for the account
- **FungibleStore without withdraw path**: A `FungibleStore` owned by a module's resource account with no function that calls `fungible_asset::withdraw` - tokens locked
- **`move_from` missing**: A resource containing value (coins, tokens) with no function that calls `move_from` to extract it - resource permanently stored
- **Object without `DeleteRef`**: An `Object` containing assets with no stored `DeleteRef` and no transfer/extraction function - assets locked in the object
- **Object without `TransferRef` and ungated_transfer disabled**: Object is non-transferable - resources inside the object are stranded
- **Frozen FungibleStore**: Store frozen with no unfreeze path - assets locked

**Severity floor enforcement**:
- If NO recovery path exists (no sweep, no admin rescue, no migration function) AND assets are currently held -> minimum **MEDIUM**
- If NO recovery path AND amount > $10,000 at protocol scale -> minimum **HIGH**
- If assets are theoretical only (not yet held) -> standard severity matrix applies

**Mandatory analysis for upgrade/migration protocols**:

| Step | Check | If Failed |
|------|-------|-----------|
| 1 | Inventory ALL asset types held pre-upgrade (APT, Coin<T>, FA, Objects) | Coverage gap |
| 2 | Does post-upgrade logic handle each asset type? | Check step 3 |
| 3 | Recovery function exists? (sweep, admin rescue, migration) | STRANDED ASSET finding |
| 4 | Apply severity floor from above | -- |

---

## Rule R10: Worst-State Severity Calibration

**Pattern**: Any severity assessment that references current on-chain state
**Check**: Is the assessment using the worst REALISTIC operational state?

When assessing severity, use the WORST REALISTIC operational state, not current on-chain snapshot:
- If protocol can hold 0 to MAX tokens -> assess at realistic peak TVL
- If fee can be 0% to 10% -> assess at boundary values
- If N users can be 1 to 10,000 -> assess at realistic maximum
- If time since last action can be 0 to MAX_DELAY -> assess at maximum delay

**Aptos-specific parameters for worst-state analysis**:
- Max transaction gas: configurable per-chain (currently ~2,000,000 gas units on mainnet)
- Max `SmartVector`/`SmartTable` size: bounded by storage costs, not hard limits
- Max event emission per transaction: no hard limit, but indexer lag at high volumes
- Block time: ~0.5-1s (fast finality)
- Max write set size per transaction: 1MB
- Max module size: 65535 bytes (module publishing limit)
- Max transaction payload: 64KB

**Current on-chain state is a SNAPSHOT, not the operational envelope.**

**Action**: For every severity assessment, state the operational parameters assumed and why. Format:
```
Severity assessed at: N_users=10000, TVL=$100M, fee=10%
Rationale: Protocol designed for up to 10,000 users per documentation
```

---

## Rule R11: Unsolicited External Token Transfer Impact (adapted from EVM R11)

**Pattern**: Protocol reads token balances or asset balances from global storage
**Check**: What happens if tokens arrive unsolicited?

**Aptos-specific vectors**:
- **APT transfer**: Anyone can send APT to any address via `aptos_account::transfer()` - creates account if needed
- **Coin<T> transfer**: Anyone can send `Coin<T>` to any address with a registered `CoinStore<T>` via `aptos_account::transfer_coins<T>()` or `coin::deposit()`
- **FungibleAsset deposit**: Anyone can deposit FA to any address's primary store via `primary_fungible_store::deposit()` - auto-creates the store if needed
- **Object creation**: Anyone can create objects whose existence might be checked by the protocol
- **Object transfer**: `object::transfer()` sends objects to any address

**5-Dimension Analysis** (for each external token/asset type):

| Dimension | Question | Impact Pattern |
|-----------|----------|----------------|
| **Transferability** | Can this asset be sent to the protocol without calling protocol functions? | If YES -> analyze all 4 dimensions below |
| **Accounting** | Does any protocol accounting query (`fungible_asset::balance`, `coin::balance<T>`, resource field reads) change when this asset arrives unsolicited? | Inflated rewards, incorrect exchange rates, fee miscalculation |
| **Operation Blocking** | Does the unsolicited asset create state that blocks protocol operations? (non-zero balances preventing removal, unexpected resource existence, unexpected object at address) | DoS on admin/keeper functions |
| **Collection Growth** | Does the unsolicited asset create new entries in any iterated collection? (`SmartVector`, `SimpleMap`, `vector`, event streams) | Gas DoS via unbounded iteration |
| **Side Effects** | Does receiving this asset trigger dispatchable hooks, event emissions, or state changes in external modules? | Reentrancy, unexpected state mutations |

**Severity floors**:
- Accounting corruption with no profitable attack -> LOW
- Operation blocking on critical functions -> minimum MEDIUM
- Gas DoS via unbounded collection growth -> minimum MEDIUM
- Profitable extraction via accounting manipulation -> standard matrix (usually HIGH)

**Action**: For every external token/asset the protocol interacts with, check if it can be transferred TO the protocol unsolicited, and trace the impact through all 5 dimensions. This includes assets returned by external module calls (LP tokens, reward tokens, receipt objects) - not just the protocol's primary token.

---

## Rule R12: Exhaustive Enabler Enumeration

**Pattern**: Any finding identifies a dangerous state S that is a precondition for exploitation
**Check**: Have ALL paths to state S been enumerated?

When a finding identifies a dangerous state (e.g., "balance reaches zero", "rate diverges from expected", "table grows unbounded"), enumerate ALL paths to that state using these 5 actor categories:

| # | Actor Category | Aptos-Specific Examples |
|---|----------------|------------------------|
| 1 | **External attacker** | Permissionless `public entry` function calls, unsolicited coin/FA/object transfers, resource/object creation at target address |
| 2 | **Semi-trusted role** | Operator/keeper acting within their capability permissions but with adversarial timing or parameter choices, `SignerCapability` abuse |
| 3 | **Natural operation** | Reward accrual, user deposits/withdrawals, fee accumulation, passage of time, epoch transitions |
| 4 | **External event** | Module upgrade, governance parameter changes, external module behavior changes, oracle staleness, framework upgrades |
| 5 | **User action sequence** | Normal user operations that in combination create an edge state via multiple entry function calls or script composition |

**Mandatory output** (for each dangerous state S identified in any finding):

| # | Path to State S | Actor Category | Existing Finding Covers It? | If Not: New Finding ID |
|---|-----------------|----------------|-----------------------------|----------------------|

**Rules**:
- Fill for ALL 5 categories. If a category cannot reach state S, document WHY (not just "N/A")
- Each MISSING path that IS reachable -> new finding or addition to existing finding
- Each new finding inherits severity from the original finding's impact assessment
- Cross-reference with Rule 5 (combinatorial): if N actors * same path -> amplified impact

**Action**: For every dangerous precondition state in the findings inventory, verify that all reachable paths have been documented. Missing paths are coverage gaps.

---

## Rule R13: User Impact Evaluation (Anti-Normalization)

**Pattern**: Any analysis concludes a behavior is "by design", "intended", or "correct architecture"
**Check**: Does this design choice harm users?

Before marking any behavior as non-issue because it appears intentional:

**5-Question Test** (ALL must be answered):
1. **Who is harmed** by this design? (specific user class: depositors, withdrawers, LPs, stakers, etc.)
2. **Can affected users avoid** the harm through their own actions? (or is it imposed on them?)
3. **Is the harm documented** in protocol documentation, comments, or UI? (informed consent?)
4. **Could the protocol achieve the same goal** without this harm? (alternative designs exist?)
5. **Does the function fulfill its stated purpose completely?** (e.g., an `emergency_withdraw` that only withdraws `Coin<AptosCoin>` but not `FungibleAsset` tokens is incomplete - users with FA deposits cannot emergency-exit)

**Verdict rules**:
- Harmed AND unavoidable AND undocumented -> FINDING (design flaw category, apply severity matrix)
- Harmed AND unavoidable AND documented -> INFO finding (users accepted known risk)
- Harmed AND avoidable -> INFO finding (user choice)
- No one harmed -> genuinely non-issue

**Aptos-specific "by design" patterns to challenge**:
- "Objects are non-deletable" - true by default, but does the protocol trap assets in non-deletable objects without extraction functions?
- "Resource accounts have no private key" - true, but was `SignerCapability` properly stored and is it accessible for all needed operations?
- "Module is immutable after publish" - true, but were all necessary admin functions included before immutability?
- "Capability pattern ensures safety" - true if capabilities are properly guarded, but are `MintRef`/`BurnRef`/`TransferRef` stored in extractable locations?
- "Module is upgradeable, admin can fix it" - upgradeability itself is a trust assumption; assess admin risk
- "FungibleAsset handles this" - does it really? Check if dispatchable hooks are registered and what they do
- "The framework handles validation" - verify: does the framework function actually check what the protocol assumes?

### Passive Attack Modeling

For ANY finding involving exchange rates, multi-step timing, or parameter updates:

Model BOTH attack types:

| Attack Type | Description | Example |
|-------------|-------------|---------|
| **Active** | Attacker front-runs or back-runs a specific transaction | Sandwich attack via transaction ordering |
| **Passive** | Attacker uses normal protocol functions at strategically chosen times, waiting for natural state changes | Deposit before accrual, withdraw after rate increase |
| **Design gap** | Protocol provides mechanism X for purpose Y, but X does not cover all cases Y requires | Emergency function that only handles Coin but not FungibleAsset, recovery that only works for some user states |

**Common passive patterns**:
- Deposit -> wait for natural reward accrual -> withdraw (timing arbitrage)
- Use normal function when parameter is at favorable boundary
- Wait for external state change (governance, oracle update) then act

**Action**: When modeling attacks, do NOT stop at "requires front-running" (active only). Always also check: "can an attacker achieve a similar result by simply timing their normal operations?" (passive).

---

## Rule R14: Cross-Variable Invariant Verification (adapted from EVM R14)

**Pattern**: Two or more state fields across global storage locations that MUST maintain a relationship for correctness (e.g., `pool.total == sum(user.amount)` across all user resources, `shares_supply == sum(balances)`)
**Check**: Can any function, admin setter, or state transition break the invariant?

**Methodology**:
1. For each aggregate variable (total, count, sum, length), identify ALL individual variables it should track - these may live in DIFFERENT resources at DIFFERENT addresses
2. For each function that modifies individual variables, verify the aggregate is updated atomically
3. For each function that modifies the aggregate directly, verify individual variables are consistent
4. Check: can the aggregate and individuals be modified through DIFFERENT code paths that desync them?
5. **Constraint coherence**: For independently-settable limits that must satisfy a mathematical relationship (e.g., `max_total == sum(max_per_pool)`), can one be changed without the other?
6. **Setter regression**: For each admin setter of a limit/bound/capacity - can the new value be set BELOW already-accumulated state? If yes, check loops (infinite iteration), comparisons (bypass), arithmetic (abort on overflow/underflow). Also check `>` vs `>=` boundary precision.

**Aptos-specific**: State may be spread across multiple resources under DIFFERENT addresses. Cross-resource invariants (e.g., `pool_resource.total_deposited == sum(user_position_resource.deposited)` across all users) are extremely hard to enforce atomically. Each `move_to`/`move_from`/`borrow_global_mut` operates on a single resource - multi-resource atomic updates require careful ordering and error handling. Within a single function execution, all changes are atomic (Move transaction atomicity), but multi-transaction state transitions can leave partial updates.

**Common invariant classes in Aptos**:
- Sum invariants: `total_supply == sum(all user balances)` across `Table<address, u64>` entries
- Count invariants: `SmartVector::length(&v) == active_count + removed_count` in a resource
- Balance invariants: `FungibleStore.balance >= sum(pending_withdrawals)` across user resources
- Table consistency: `Table` contains an entry for every key in a parallel `SmartVector` of keys
- Cross-resource consistency: Config resource limits match sum of per-entity resource allocations
- Constraint coherence: `global_cap >= sum(pool_caps)` across independently-settable pool config resources
- Object-resource consistency: `Object<T>` existence matches resource existence at the object address

**Action**: For every aggregate/total variable, trace ALL modification paths for both the aggregate AND its components - especially when they live in different resources or are accessed through different functions. If any path modifies one without the other -> FINDING. For every admin setter of a limit/bound, verify it cannot regress below accumulated state.

---

## Rule R15: Flash Loan Precondition Manipulation (adapted from EVM R15)

**Pattern**: Any function precondition that depends on state manipulable via borrowed capital within a single transaction
**Check**: Can the precondition be satisfied/bypassed atomically within a single transaction?

**Aptos flash loan patterns**: Unlike EVM's callback model, Aptos flash loans typically use the **hot potato pattern** - a resource struct without `drop` or `store` ability that MUST be consumed (returned) before the transaction completes:

```move
// Borrow: returns Coin + FlashLoanReceipt (no drop, no store)
public fun flash_borrow<T>(pool: &mut Pool<T>, amount: u64): (Coin<T>, FlashLoanReceipt<T>)
// Repay: consumes FlashLoanReceipt (only way to dispose of it)
public fun flash_repay<T>(pool: &mut Pool<T>, coin: Coin<T>, receipt: FlashLoanReceipt<T>)
```

| State Type | Manipulation Method | Flash Accessible? | Check |
|-----------|-------------------|-------------------|-------|
| `coin::balance<T>(addr)` | Donation / deposit | YES (0 cost) | Can inflated balance bypass checks? |
| `fungible_asset::balance(store)` | Deposit via `primary_fungible_store::deposit` | YES (0 cost) | Can inflated FA balance bypass checks? |
| Oracle spot price | Trade on source DEX pool | YES (slippage cost) | Is spot used instead of TWAP? |
| Threshold / quorum | Deposit / stake | YES (deposit amount) | Can threshold be crossed atomically? |
| Exchange rate | Deposit to inflate shares denominator | YES | Does rate affect minting/redemption? |
| Collateral ratio | Deposit collateral temporarily | YES | Can temporary collateral enable actions? |

**Mandatory sequence modeling**: For each flash-accessible state, model the full atomic sequence:
1. BORROW (flash_borrow - hot potato receipt created) -> 2. MANIPULATE (deposit/trade to inflate target state) -> 3. CALL target function (exploit) -> 4. EXTRACT value -> 5. RESTORE state -> 6. REPAY (flash_repay - consume receipt)
7. Compute: profit = extracted_value - flash_fee - gas. If profit > 0 -> FINDING.

**Hot potato enforcement check**: Verify flash loan receipts:
- Have NO `drop` ability (cannot be silently discarded - skipping repayment)
- Have NO `store` ability (cannot be stored to persist across transactions)
- Are consumed ONLY by the repayment function with correct amount validation
- Repayment function validates amount repaid >= amount borrowed + fee

**Action**: For every function with a balance/oracle/threshold/rate precondition, check if a flash loan (hot-potato pattern or lending protocol borrow within same transaction) can satisfy it atomically. See FLASH_LOAN_INTERACTION skill for full methodology.

---

## Rule R16: Oracle Integrity (adapted from EVM R16)

**Pattern**: Any module logic that consumes oracle data for decisions
**Check**: Is the oracle data validated for all failure modes?

| Check | Pyth on Aptos | Switchboard on Aptos | Custom Oracle Module |
|-------|--------------|---------------------|---------------------|
| Staleness | `price.timestamp` checked against max age | Aggregator round timestamp checked | Stored timestamp vs `timestamp::now_seconds()` |
| Confidence | `price.conf` vs `price.price` ratio checked | Confidence interval checked | N/A or module-specific |
| Price > 0 | `price.price > 0` validated | `result > 0` validated | Explicit zero check |
| Exponent handling | `price.exponent` (negative, e.g., -8) correctly applied | Decimals from feed config matched | Decimals matched to consumer expectations |
| Feed ID verification | Price feed object ID validated against known constant | Aggregator address validated | Oracle resource address validated |
| Status/freshness | `pyth::update_price_feeds` called in same tx or recently | Aggregator not stale | Update recency checked |
| TWAP window | If using EMA price: window length vs pool liquidity | N/A | Custom TWAP window validated |
| Fallback | What happens if Pyth module aborts? | What happens if Switchboard aborts? | What happens if oracle read aborts? |
| Config bounds | Oracle config setters (window size, deviation, heartbeat) have meaningful min/max | Same | Same |

**Pyth on Aptos specifics**: Pyth uses a **pull model** - price feeds must be updated within the same transaction via `pyth::update_price_feeds`. Check: (1) what if the update instruction is omitted from the transaction? Does the module use stale cached data? (2) is `max_age` enforced? (3) is the Pyth state object address validated against a known constant?

**Action**: For every oracle data consumption point, verify ALL applicable checks from the table above. Missing checks -> FINDING at severity based on impact. See ORACLE_ANALYSIS skill for full methodology.
- For every oracle configuration setter (window size, max deviation, heartbeat), check: can the parameter be set to a value that effectively disables the oracle validation? If yes -> FINDING (Rule 14 setter regression applies).

---

## Rule R17: State Transition Completeness

**Pattern**: Operations with symmetric branches - profit/loss, deposit/withdraw, mint/burn, stake/unstake, increase/decrease
**Check**: All state fields modified in one branch are either (a) also modified in the other branch, or (b) explicitly documented as intentionally asymmetric.

**Methodology**:
1. For each pair of symmetric operations, list ALL state fields modified by the "positive" branch (profit, deposit, mint, stake, increase)
2. For the "negative" branch (loss, withdraw, burn, unstake, decrease), verify each field from step 1 is also handled
3. If a field is missing from the negative branch: trace what happens to dependent computations when that field retains its old value while other fields changed
4. Flag branch size asymmetry > 3x in code volume (lines of code) as a review trigger - large asymmetry often indicates incomplete handling

**Common miss patterns**:
- Profit branch updates `locked_profit` + `total_value` + `high_water_mark`, loss branch updates only `total_value` -> `locked_profit` can exceed `total_value` -> arithmetic abort
- Deposit updates `total_deposited` in vault resource + mints share coins, emergency withdraw burns shares but does not update `total_deposited` -> accounting desync
- Stake updates `total_staked` + `last_stake_time`, unstake updates `total_staked` but not `last_stake_time` -> stale time-dependent calculations

**Aptos-specific**: State may be spread across multiple resources at different addresses (vault config resource, pool state resource, user position resource, Object-stored data). Ensure ALL resources updated in the positive branch are also updated in the negative branch. Pay special attention to `Table`/`SmartTable` entries that may not be cleaned up in the negative branch, and Object resources that may retain stale data after the negative operation.

**Action**: For every operation pair, produce a field-by-field comparison table. Missing fields in the negative branch that have dependent consumers -> FINDING.

---

## Rule MR1: Ability Analysis (Shared Move Rule)

**Pattern**: Every struct definition with ability annotations (`copy`, `drop`, `store`, `key`)
**Check**: Are the declared abilities security-appropriate for the struct's purpose?

| Ability | Grants | Security Risk If Misapplied |
|---------|--------|-----------------------------|
| `copy` | Value can be duplicated via implicit/explicit copy | Token/receipt/capability duplication - value created from nothing |
| `drop` | Value can be silently discarded (goes out of scope without consumption) | Obligation bypass - hot-potato receipt silently dropped instead of consumed |
| `store` | Value can be placed in global storage by any module with `key` access | Value escapes module control - can be stored in attacker-controlled resources |
| `key` | Value can exist as top-level resource in global storage via `move_to` | Resource can be `move_to`/`move_from`'d - unauthorized storage or extraction |

**Mandatory checks per struct category**:

1. **Value tokens** (coins, shares, receipts representing economic value): MUST NOT have `copy` (prevents duplication). `Coin<T>` and `FungibleAsset` correctly lack `copy`.
   ```move
   struct Ticket has copy, drop { value: u64 } // BUG: copy allows using ticket twice
   // Correct: struct Ticket has store { value: u64 }
   ```

2. **Hot-potato / obligation structs** (flash loan receipts, lock tickets): MUST NOT have `drop` (forces consumption). MUST NOT have `store` or `key` (prevents stashing to avoid consumption within the transaction).
   ```move
   struct FlashLoanReceipt has drop { amount: u64 } // BUG: drop allows skipping repayment
   // Correct: struct FlashLoanReceipt { amount: u64 } // No abilities = must be consumed
   ```

3. **Capability structs** (admin caps, mint rights, signer capabilities): SHOULD NOT have `copy` (prevents capability duplication). SHOULD NOT have `store` unless intentional delegation is designed.
   ```move
   struct MintCap has copy, store { ref: MintRef } // BUG: copy allows duplication
   // Correct: struct MintCap has store { ref: MintRef } // store only for controlled persistence
   ```

4. **Witness / type-witness structs** (one-time-use proofs for module initialization): SHOULD NOT have `copy` or `store` (ensures single use within module initialization).
   ```move
   struct InitWitness has drop {} // Correct: used once, then dropped
   struct InitWitness has copy, drop {} // BUG: copy allows reuse
   ```

5. **Phantom type parameters**: `phantom T` means T is not used at runtime, only at compile-time type checking. If no runtime type check exists, attacker can instantiate with any T.
   ```move
   struct Wrapper<phantom T> has key, store { value: u64 }
   // Can be instantiated as Wrapper<FakeToken> if no runtime type_info check
   ```

**Action**: For every struct in scope, verify abilities match the struct's security role. Flag: `copy` on value types, `drop` on obligation types, `store` on capability types that should not be transferable. Enumerate all structs with `copy` or `drop` that hold value or represent uniqueness.

---

## Rule MR2: Bit-Shift Safety (Shared Move Rule)

**Pattern**: Any use of `<<` (left shift) or `>>` (right shift) operators
**Check**: Is the shift amount guaranteed to be less than the bit width of the operand type?

**CRITICAL**: Move aborts on shift >= bit width. This was the root cause of the **$223M Cetus hack** where an unchecked shift amount in a fixed-point math library produced 0 instead of the expected value, enabling an attacker to drain liquidity pools.

**Vulnerability pattern**:
```move
let result = 1u128 << amount; // If amount >= 128, ABORTS (DoS) or produces 0 (on some VMs)!
```

| Operand Type | Bit Width | Max Safe Shift | Required Assert |
|-------------|-----------|---------------|-----------------|
| `u8` | 8 | 7 | `assert!(shift_amount < 8, E_SHIFT_OVERFLOW)` |
| `u16` | 16 | 15 | `assert!(shift_amount < 16, E_SHIFT_OVERFLOW)` |
| `u32` | 32 | 31 | `assert!(shift_amount < 32, E_SHIFT_OVERFLOW)` |
| `u64` | 64 | 63 | `assert!(shift_amount < 64, E_SHIFT_OVERFLOW)` |
| `u128` | 128 | 127 | `assert!(shift_amount < 128, E_SHIFT_OVERFLOW)` |
| `u256` | 256 | 255 | `assert!(shift_amount < 256, E_SHIFT_OVERFLOW)` |

**Mandatory checks**:
1. Is the shift amount a literal constant? (SAFE - compiler validates)
2. Is the shift amount derived from user input or computed from state? (CHECK bounds)
3. Is the shift amount bounded by an explicit check before the shift operation? (SAFE if bound < bit width)
4. Can the computation path produce a shift amount >= bit width under ANY input? (FINDING if yes)
5. For compound expressions: trace the shift amount to its source, verify bounds at every step

**Impact**: If used in price/amount calculation, can produce 0 where nonzero expected -> division by zero, infinite minting, free extraction. If abort: DoS on all dependent functions.

**Action**: For every `<<` and `>>` operation in the codebase, trace the shift amount to its source. If user-controlled or computed without bounds checking, flag as potential Critical finding (extraction) or minimum Medium (DoS via abort).

---

## Rule MR3: Type Safety - Generic and Phantom Type Parameters (Shared Move Rule)

**Pattern**: Functions or structs with generic type parameters (`<T>`, `<phantom T>`)
**Check**: Can an attacker substitute unexpected types to bypass security invariants?

Move's type system is strong at compile time but generic functions can be instantiated with ANY type satisfying ability constraints. Runtime validation is needed when business logic depends on specific types.

**Attack vectors**:

| Vector | Description | Example |
|--------|-------------|---------|
| Generic type substitution | Attacker calls `deposit<FakeToken>()` instead of `deposit<USDC>()` | Deposits worthless token, withdraws valuable token |
| Phantom type confusion | `Pool<phantom A, phantom B>` instantiated with swapped types | Pair confusion in DEX |
| Type witness forgery | Module expects `TypeWitness<T>` as proof of authorization but `T` is attacker-controlled | Authorization bypass |
| Missing type constraints | Generic `T` without required ability constraints allows unexpected types | `T: store` missing causes abort with non-storable types |
| `mem::swap` attacks | Mutable references (`&mut T`) swapped via `std::mem::swap` | Swap zero-value coin for vault's full-value coin if both `&mut` refs accessible |

**Mandatory checks**:
1. For every generic type parameter in public functions: is it constrained to expected types (via type witness, allowlist, or module-level restriction)?
   ```move
   public fun deposit<T>(coin: Coin<T>) {
       // Must validate T is an approved coin type, not any random Coin<T>
       assert!(type_info::type_of<T>() == type_info::type_of<USDC>(), E_INVALID_COIN);
   }
   ```
2. For every phantom type parameter: does the phantom type correctly enforce type-level invariants (e.g., `Coin<phantom CoinType>` distinguishes different coins)?
3. For every type witness pattern: is the witness consumed (not copyable) and generated only by authorized modules?
4. Are ability constraints on type parameters sufficient? (e.g., `T: key + store` when only `key` is needed exposes to `store`-based attacks)
5. Can `mem::swap` be used to exchange valuable mutable references? Check if a function takes `&mut Coin<T>` and the attacker can provide their own mutable reference of the same type.

**Action**: For every generic function and struct, verify type parameters cannot be adversarially substituted. Pay special attention to `public entry` functions where the type parameter is supplied by the transaction sender.

---

## Rule MR4: Dependency Audit (Shared Move Rule)

**Pattern**: External module dependencies via `use` statements
**Check**: Are dependencies trusted, interface-stable, and upgrade-risk assessed?

**Aptos dependency categories**:

| Category | Trust Level | Check |
|----------|-----------|-------|
| `aptos_framework::*` | HIGH (governance-controlled) | Interface stability across framework upgrades |
| `aptos_std::*` | HIGH (governance-controlled) | Same as above |
| `aptos_token_objects::*` | HIGH (governance-controlled) | Same as above |
| Third-party published modules | VARIABLE | Publisher identity, upgrade policy, code audit status |
| Protocol's own modules | SELF | Internal consistency, correct `friend` declarations |

**Mandatory checks**:

1. **Upgrade policy assessment**: For each dependency, determine upgrade policy:
   | Policy | Risk | Check |
   |--------|------|-------|
   | Immutable | None - code cannot change | Safe |
   | Compatible | Can add functions, cannot change existing signatures | Low - new functions could create unexpected entry points |
   | Arbitrary | Can change anything | HIGH - all assumptions about behavior may break |

2. **Interface stability**: Does the module use the external function's EXACT signature? Compatible upgrades can add functions but not change existing signatures in Aptos.

3. **Trust boundary**: Is the dependency publisher's address validated (not spoofable)? Module addresses are part of the fully-qualified name - but verify the address is the expected one.

4. **Transitive dependencies**: Does the dependency itself depend on modules that could be upgraded? A dependency's dependency being upgradeable can also change behavior.

5. **Framework dependency awareness**: Dependencies on `aptos_framework`, `aptos_std`, `aptos_token_objects` are governed by Aptos governance and can change via framework upgrades. Rare but possible - note as trust assumption.

**Action**: For every `use` statement importing from a non-framework module, assess upgrade risk and interface stability. Flag dependencies on upgradeable third-party modules as trust assumptions.

---

## Rule MR5: Visibility Audit (Shared Move Rule)

**Pattern**: Function visibility declarations (`public`, `public(friend)`, `entry`, internal)
**Check**: Is each function's visibility the minimum required for its purpose?

| Visibility | Who Can Call | Risk Level |
|-----------|------------|-----------|
| (none - internal) | Only the defining module | LOWEST - fully controlled |
| `public(friend)` | Only declared `friend` modules | LOW - controlled set of callers |
| `entry` | External transactions only (not other modules) | MEDIUM - any user can call, but not composable by other modules |
| `public` | Any module | HIGH - fully composable, any caller module |
| `public entry` | Both external transactions and other modules | HIGHEST - both composable and directly callable |

**Mandatory checks**:

1. **Over-exposure**: Functions that modify sensitive state (balances, config, capabilities) should not be `public` unless composition is intentionally designed. Check if `entry`-only or `public(friend)` would suffice.

2. **`friend` audit**: Every `friend` declaration grants the friend module access to ALL `public(friend)` functions. Verify each friend module actually needs access to all of them. An overly broad friend list widens the trust boundary.

3. **`entry` vs `public` vs `public entry`**:
   - `entry` functions cannot be called via module composition. Use this when composability is NOT wanted (prevents flash loan integration, sandwich attacks via composed calls).
   - `public` functions can be called by other modules but NOT directly from transactions (unless also `entry`).
   - `public entry` functions can be called BOTH ways - double exposure surface.

4. **Missing `entry`**: Functions that should be callable by users but are only `public` (not `entry`) cannot be called directly from transactions - only via scripts or other modules.

5. **`#[view]` verification**: Functions marked `#[view]` are expected to be read-only. Verify they truly do not modify state (no `borrow_global_mut`, no `move_to`, no `move_from`).

6. **State-modifying public functions without signer**: Functions marked `public` that modify global state without requiring `&signer` parameter - any module can call these to mutate state.

**Action**: For every function in scope, verify visibility is the minimum necessary. Flag `public` functions that should be `public(friend)` or `entry`-only, `public entry` functions where only `entry` was intended, and `friend` declarations that grant excessive access. Enumerate all state-modifying `public` functions without signer checks.

---

## Rule AR1: Reference Capability Lifecycle (Aptos-Specific)

**Pattern**: Creation and storage of Object/FungibleAsset reference capabilities (`ConstructorRef`, `TransferRef`, `MintRef`, `BurnRef`, `DeleteRef`, `ExtendRef`)
**Check**: Are capabilities properly scoped, stored securely, and not leaked?

**Capability generation chain**:
```
ConstructorRef (ephemeral - no store ability)
  |-- generates TransferRef (has store - can be persisted)
  |-- generates MintRef (has store - can be persisted)
  |-- generates BurnRef (has store - can be persisted)
  |-- generates ExtendRef (has store - can be persisted)
  |-- generates DeleteRef (has store - can be persisted)
```

**Security checks**:

| Check | What to Verify | Impact if Failed |
|-------|---------------|-----------------|
| ConstructorRef consumed | Used only within creation function, never stored (has no `store` by design) | N/A (compiler prevents storing, but verify no workarounds via wrapping) |
| TransferRef access | Who can access the stored TransferRef? | Unauthorized object movement - can transfer/move the object WITHOUT owner consent |
| MintRef access | Who can access the stored MintRef? | Infinite minting - grants UNLIMITED minting of the FungibleAsset |
| BurnRef access | Who can access the stored BurnRef? | Token destruction - grants ability to DESTROY any token of that FA from any store |
| ExtendRef access | Who can access the stored ExtendRef? | Object control - `generate_signer_for_extending` = equivalent to having the object's private key |
| DeleteRef access | Who can access the stored DeleteRef? | Object destruction - can delete the object and all its resources |
| Ref wrapping | Is the Ref stored inside a struct with `copy` ability? | Capability duplication - infinite refs created from one |
| Ref revocation | Can Refs be moved into a consuming function to destroy them? | If no revocation path, capability is permanent and irrevocable |
| Missing Ref generation | Was a needed Ref NOT generated during construction? | Permanent inability - e.g., no `DeleteRef` means object can never be deleted, no `TransferRef` with ungated_transfer disabled means object is permanently immovable |

**Critical patterns**:

1. **MintRef stored with public accessor**: Anyone with access can mint unlimited tokens
   ```move
   struct Config has key {
       mint_ref: MintRef,
   }
   public fun get_mint_ref(): &MintRef { // BUG: public access to MintRef
       &borrow_global<Config>(@module_addr).mint_ref
   }
   ```

2. **TransferRef not properly guarded**: Object can be moved without owner's consent
3. **ExtendRef leaked**: `object::generate_signer_for_extending(&extend_ref)` grants full object signer - equivalent to having the object's private key
4. **Refs stored in transferable object**: If the object holding refs has an active `TransferRef`, transferring the object transfers all capabilities with it
5. **Ref in copyable wrapper**: Wrapping a ref in a `copy`-able struct duplicates the capability

**Action**: For every object creation in the codebase, trace the `ConstructorRef` through all `generate_*_ref` calls. For each generated ref, trace: (1) storage location (which resource, under which address), (2) all access paths (function visibility + signer checks), (3) whether it can be duplicated (wrapping struct abilities), (4) whether it can be destroyed (revocation path). Flag: stored `ConstructorRef`, publicly accessible `MintRef`/`BurnRef`/`ExtendRef`, missing `DeleteRef`/`TransferRef` for objects holding assets.

---

## Rule AR2: FungibleAsset Compliance - Dispatchable Hooks (Aptos-Specific)

**Pattern**: Modules that register or interact with dispatchable function hooks for FungibleAsset operations
**Check**: Are hooks safe from reentrancy, complete in coverage, and bypass-resistant?

**Dispatchable hooks available**:

| Hook | Triggered When | Registration |
|------|---------------|-------------|
| `withdraw` | Any withdrawal from a `FungibleStore` of this asset type | `dispatchable_fungible_asset::register_dispatch_functions` |
| `deposit` | Any deposit into a `FungibleStore` of this asset type | Same registration |
| `derived_balance` | Balance query for a `FungibleStore` of this asset type | Same registration |

**Mandatory checks**:

1. **Reentrancy via hooks**: If a module's withdraw hook calls another module which calls back into the first module, global storage may be in an inconsistent state. Verify: are all relevant resources in a consistent state BEFORE the hook is triggered? (Checks-Effects-Interactions pattern)

2. **Hook completeness**: Do hooks handle all token amounts correctly? Edge cases: zero amount, max amount, store with zero balance.

3. **Bypass via direct FungibleStore operations**: Can the hook be bypassed by calling `fungible_asset::withdraw` directly (with `WithdrawRef`) instead of going through `dispatchable_fungible_asset::withdraw`? Check: who holds the `WithdrawRef`?

4. **Hook abort risk**: If a deposit or withdraw hook aborts, ALL transfers of this asset type are blocked. Is the hook designed to never abort under normal conditions? Can an attacker trigger conditions that cause the hook to abort (DoS)?

5. **Derived balance manipulation**: If `derived_balance` hook returns a manipulated value, how does this affect protocol accounting? Can an attacker influence the hook's return value?

6. **Store existence and metadata validation**: Before operating on a FungibleStore, verify it exists (or use `primary_fungible_store` which auto-creates). When accepting FA, validate the metadata object matches the expected asset type.

7. **Frozen store handling**: Check if store is frozen before operations - frozen stores reject deposits/withdrawals.

8. **Primary vs secondary stores**: `primary_fungible_store` creates one default store per address per FA type; secondary stores are separate. Verify protocol checks the correct store.

**FungibleAsset vs Legacy Coin<T> comparison**:

| Feature | Legacy Coin<T> | FungibleAsset |
|---------|---------------|---------------|
| Hooks | None | DepositHandler, WithdrawHandler, TransferHandler, derived_balance |
| Auto-creation | No (must register CoinStore) | Yes (primary_fungible_store auto-creates) |
| Parallel execution | No | Yes (ConcurrentFungibleBalance) |
| Ref-based control | No | MintRef, TransferRef, BurnRef |
| Type safety | Compile-time via phantom T | Runtime via metadata object address |

**Action**: For every FungibleAsset type the protocol defines or interacts with, check if dispatchable hooks are registered. If yes, verify all checks above. If the protocol CONSUMES an external FungibleAsset with hooks, verify the protocol is resilient to arbitrary hook behavior.

---

## Rule AR3: Reentrancy via Module Calls and Closures (Aptos-Specific)

**Pattern**: Module A calls Module B which calls Module A back (directly or transitively), or function values/closures executing external code
**Check**: Is global storage in a consistent state before external module calls or closure execution?

**CRITICAL**: Aptos Move is NOT inherently reentrancy-free. While the borrow checker prevents borrowing the same resource twice within a single function, cross-module call chains and closures can create reentrancy-equivalent conditions.

**Reentrancy patterns in Move**:

| Pattern | How It Happens | Impact |
|---------|---------------|--------|
| Global storage inconsistency | Module A updates resource X partially, calls Module B, Module B reads stale/inconsistent view of A's state | State corruption, double-spending |
| `borrow_global_mut` abort | Module A holds `&mut` to Resource R, calls Module B, Module B tries to `borrow_global_mut<R>` same resource -> abort | DoS (transaction reverts) |
| Dispatchable hook callback | Module A calls `dispatchable_fungible_asset::withdraw`, hook in Module B calls back into Module A | Classic reentrancy if state not finalized before call |
| Function values / closures (Move 2.0) | Higher-order function accepts caller-provided closure that calls back into current module | Reentrancy via callback if closure modifies state the caller hasn't finalized |
| Transitive call chain | A -> B -> C -> A via public functions | Unexpected reentry into A while A's state is mid-update |

**Mandatory checks**:

1. **State-before-interaction**: Before ANY cross-module call, are all global resource mutations COMPLETE? (Checks-Effects-Interactions pattern adapted for Move)
   ```move
   // CORRECT: Checks-Effects-Interactions
   fun withdraw(user: &signer, amount: u64) {
       let pool = borrow_global_mut<Pool>(@pool_addr);
       assert!(pool.balance >= amount, E_INSUFFICIENT);  // CHECK
       pool.balance -= amount;                             // EFFECT
       pool.total_withdrawn += amount;                     // EFFECT
       fungible_asset::withdraw(ref, store, amount);       // INTERACTION (may trigger hook)
   }

   // WRONG: Interaction before effect
   fun withdraw(user: &signer, amount: u64) {
       let pool = borrow_global_mut<Pool>(@pool_addr);
       assert!(pool.balance >= amount, E_INSUFFICIENT);
       fungible_asset::withdraw(ref, store, amount);       // INTERACTION (hook can re-enter!)
       pool.balance -= amount;                             // EFFECT (too late if re-entered)
   }
   ```

2. **Borrow-across-call**: Does the module hold a `&mut` reference to a global resource while making an external module call? If Module B transitively calls back, this will abort - is this the intended defense (reentrancy guard via borrow checker) or an unintended DoS?

3. **Dispatchable hook awareness**: If the module operates on FungibleAssets with dispatchable hooks, does it account for arbitrary code execution during deposit/withdraw? Are all state changes complete before the FA operation?

4. **Closure/function value safety**: For every closure or function value passed to or received from an external module, can it call back into the current module's `public` or `public entry` functions?

5. **Transitive call chains**: Map the full call graph: A -> B -> C chains. Can C call back into A? Document the chain and verify state consistency at each call boundary.

**Action**: For every external module call (any function call to a module not defined in the current package) and every closure/function-value execution, verify global storage is in a consistent state before the call. Map the full call graph for reentrancy-equivalent patterns. Flag any path where state is updated after an external call that could re-enter.

---

## Rule AR4: Randomness API Safety (Aptos-Specific)

**Pattern**: Usage of `aptos_framework::randomness` module
**Check**: Is randomness used safely with proper API constraints?

**Aptos randomness API requirements**:

| Check | What to Verify | Impact if Missing |
|-------|---------------|-------------------|
| `#[randomness]` attribute | Function using randomness has `#[randomness]` annotation | Undergasing attack - caller aborts tx if random result is unfavorable, biasing outcomes |
| Entry-only constraint | Randomness function should be `entry` only (NOT `public` or `public entry`) | Composable call wrapper can observe result and selectively abort |
| No test-and-abort | Caller cannot observe randomness result and abort if unfavorable | Biased randomness - attacker only accepts favorable outcomes |
| Commit-reveal separation | If used for lottery/selection, is there a commit phase before reveal? | Front-running the randomness result |
| Single consumption | Is the random value used exactly once? | Reuse leaks entropy, correlation attacks |

**Undergasing attack pattern**:
```move
// VULNERABLE: No #[randomness] attribute
public entry fun lottery(user: &signer) {
    let result = randomness::u64_range(0, 100);
    if (result < 10) {
        // User wins! Attacker provides just enough gas for this branch
        award_prize(user);
    } else {
        // User loses. Attacker provides insufficient gas, tx aborts, no cost
        record_loss(user);
    }
}

// SAFE: #[randomness] prevents undergasing
#[randomness]
entry fun lottery(user: &signer) {
    let result = randomness::u64_range(0, 100);
    // #[randomness] ensures tx cannot be aborted by gas manipulation
    // after randomness is consumed
}
```

**Composability attack pattern**:
```move
// VULNERABLE: public entry allows composition
#[randomness]
public entry fun lottery(user: &signer) { // BUG: public allows other modules to call
    // Another module can: call lottery -> observe state change -> abort if unfavorable
}

// SAFE: entry only prevents composition
#[randomness]
entry fun lottery(user: &signer) { // Only callable from transactions, not other modules
}
```

**Mandatory checks**:
1. Does the function using `randomness::*` have `#[randomness]` attribute?
2. Is the function `entry`-only (NOT `public` or `public entry`)? If `public`, can another module call it, observe the result, and abort the transaction if unfavorable?
3. Can the transaction caller observe the randomness result and conditionally abort (test-and-abort attack)?
4. Is the random value committed to state before it can be observed by any external party?
5. Is the same random value used in multiple independent decisions? (correlation risk)

**Action**: For every usage of `aptos_framework::randomness`, verify all 5 checks. A `public` or `public entry` function using randomness that allows composition is a HIGH severity finding (biased randomness). Missing `#[randomness]` attribute is a HIGH severity finding (undergasing attack).

---

## Evidence Source Tags - Aptos

| Tag | Description | Valid for REFUTED? |
|-----|-------------|-------------------|
| [PROD-ONCHAIN] | Read from production Aptos account on-chain | YES |
| [PROD-SOURCE] | Verified source from Aptos Explorer | YES |
| [PROD-FORK] | Tested on local Aptos node with mainnet state dump | YES |
| [CODE] | From audited codebase source | YES |
| [MOCK] | From mock/test setup | **NO** |
| [EXT-UNV] | External, unverified | **NO** |
| [DOC] | From documentation only | **NO** |

**Any REFUTED verdict where ALL external behavior evidence is tagged [MOCK], [EXT-UNV], or [DOC] is automatically escalated to CONTESTED.** Only [PROD-ONCHAIN], [PROD-SOURCE], [PROD-FORK], and [CODE] tags can support REFUTED for external module behavior.

---

## Enforcement Mechanisms

### Devil's Advocate FORCING

When any agent identifies a potential attack path with "could" or "might":
- MUST pursue the path to conclusion (CONFIRMED/REFUTED with evidence)
- "Further investigation needed" -> MUST do the investigation NOW

### CONTESTED Triggers Production Fetch

When any finding gets CONTESTED verdict:
1. Orchestrator MUST spawn production verification
2. If production source unavailable -> stays CONTESTED (not REFUTED)
3. CONTESTED findings get same verification priority as HIGH severity

### REFUTED Priority Chain Analysis

Before any finding is marked REFUTED:
1. Chain analyzer MUST search ALL other findings for enablers
2. If potential enabler exists -> PARTIAL (not REFUTED)
3. Only mark REFUTED if NO plausible enabler exists

### Cross-Validation Before REFUTED

Before marking ANY finding REFUTED, the analyst MUST:
1. State what evidence would PROVE this IS exploitable
2. Confirm they have checked for that evidence
3. If evidence is unavailable (not "doesn't exist") -> CONTESTED

### Evidence Source Enforcement

[MOCK], [EXT-UNV], and [DOC] evidence CANNOT support a REFUTED verdict for findings involving external module behavior. Only [PROD-ONCHAIN], [PROD-SOURCE], [PROD-FORK], or [CODE] evidence (direct source reading of the external module) qualifies.
