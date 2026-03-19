# Generic Security Rules - Sui Move

> **Usage**: Analysis agents and depth agents reference these rules during Sui Move module analysis.
> These rules cover ALL Sui Move modules regardless of type. Rules R1-R17 are adapted from EVM equivalents. Rules MR1-MR5 are shared Move rules. Rules SR1-SR4 are Sui-specific.

---

## Rule R1: Module Call Return and Object Validation (adapted from EVM R1)

**Pattern**: Any call to external package functions that returns objects or values
**Check**: Does the ACTUAL return type match what the consuming module EXPECTS? Are object type parameters validated?

| Mismatch Type | Example | Impact |
|---------------|---------|--------|
| Generic type confusion | `Coin<FakeToken>` passed where `Coin<USDC>` expected | Wrong token processed, vault drain |
| Object type parameter mismatch | `Pool<A, B>` vs `Pool<B, A>` | Swapped token pair, incorrect pricing |
| Balance unwrap mismatch | `Balance<T>` unwrapped to wrong `Coin<T>` | Accounting corruption |
| Dynamic field type confusion | Dynamic field read with wrong type parameter | Deserialized data misinterpretation, abort |
| Package version mismatch | V1 object passed to V2 function expecting V2 layout | Field misalignment, data corruption |

**Sui key difference**: Sui Move has NO reentrancy. There are no callbacks, no hooks, no closures executing during external calls. External module calls are synchronous and complete before control returns. Focus analysis on: return type validation, object type parameter validation (`Coin<FakeToken>` vs `Coin<USDC>`), and dynamic field type confusion.

**Action**: For every external module call returning objects or values: (1) trace the generic type parameters through all instantiation paths, (2) verify `Coin<T>` type constraints are enforced at the entry function level not just internally, (3) for dynamic field access, verify the key-value type pair matches what was stored.

---

## Rule R2: Function Preconditions Are Griefable (adapted from EVM R2)

**Pattern**: Any `public` or `entry` function with preconditions based on externally-manipulable state
**Check**: Can external actors manipulate state to make the precondition fail or succeed at the wrong time?

```move
public entry fun keeper_harvest(pool: &mut Pool, clock: &Clock) {
    assert!(balance::value(&pool.rewards) > pool.min_threshold, E_INSUFFICIENT); // USER CAN DONATE TO EXCEED OR DRAIN
    // ...
}
```

This includes:
- Admin/keeper functions with user-manipulable preconditions
- **Permissionless functions with oracle-dependent preconditions** (e.g., liquidation requires price < threshold -- can price feed be manipulated within a PTB?)
- **Permissionless functions with balance-dependent preconditions** (e.g., function requires `coin::value(&coin) > X` -- can deposits/withdrawals manipulate?)
- **Shared object state preconditions** -- any function reading shared object state that another transaction can modify concurrently

**Direction 2 -- Admin action impacts on user functions**: For every admin setter that modifies a parameter used in user-facing function preconditions or logic:
1. Can an admin parameter change make a user-facing function behave unexpectedly? (e.g., setting `max_slippage = 0` blocks all swaps)
2. Does the admin change retroactively affect users in active positions? (e.g., changing fee rate while users have pending claims)
3. Can the admin transfer or share a capability object that changes access control? (`AdminCap` with `store` -> transferable by anyone who holds it)

**Sui-specific vectors**:
- **PTB atomic composition**: Attacker composes manipulate() + exploit() in a single Programmable Transaction Block
- **Unsolicited object transfer**: Anyone can `transfer::public_transfer` any object with `store` ability to any address (including `Coin<SUI>`, custom objects)
- **Shared object contention**: Attacker submits transactions modifying shared object state to grief preconditions for other users' transactions in the same epoch
- **Coin splitting/merging**: `coin::split` and `coin::join` allow arbitrary balance manipulation before calling target functions within a single PTB

**Action**: For every function with a precondition, identify whether the precondition state can be manipulated by: (1) direct user action (deposit/withdraw/transfer), (2) PTB composition within the same transaction block, (3) `Coin<T>` donation (unsolicited `transfer::public_transfer` to any address), (4) concurrent shared object modification.

---

## Rule R3: Transfer Side Effects (adapted from EVM R3)

**Pattern**: Any transfer of objects or coins to/from external modules
**Check**: Does the operation trigger side effects?

**Sui key difference**: Sui has NO transfer hooks, NO callbacks, NO dispatchable hooks. `Coin<T>` and `Balance<T>` transfers are pure state changes with no external code execution. This is fundamentally safer than EVM (ERC777/ERC1363 hooks) and Aptos (dispatchable fungible asset hooks).

| Operation | Side Effects? | Check |
|-----------|:------------:|-------|
| `coin::split` / `coin::join` | None | Safe -- pure arithmetic on Coin values |
| `transfer::public_transfer` (Coin) | None | Safe -- ownership change only |
| `balance::join` / `balance::split` | None | Safe -- value change only |
| `transfer::transfer` (key-only object) | None | Safe -- module-restricted ownership change |
| Custom wrapper object destroy/unwrap | **Possible** | Module-defined logic in `destroy` functions may release Balance, emit events, update counters |
| Dynamic field add/remove | **Possible** | May invalidate parent object invariants, change enumeration counts |
| Object wrapping (into another object) | **Possible** | Wrapped object loses RPC visibility; lifecycle bound to parent |
| `balance::destroy_zero` | Aborts if != 0 | Ensure zero balance before call or handle abort |

**Mandatory check**: For every object the protocol transfers, wraps, or destroys:
- [ ] Does the object have custom destroy/unwrap logic?
- [ ] Does destruction release inner `Balance<T>` or nested objects?
- [ ] Does wrapping in a dynamic field create an inaccessible state?
- [ ] Are events emitted correctly on transfer/destroy for indexer accuracy?

**Output requirement** (in attack_surface.md Object Flow Matrix):
| Object Type | On-Transfer/Destroy Side Effect | Documented? | Verified? |
|-------------|-------------------------------|-------------|-----------|

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

**Sui-specific uncertainty sources**:
- **Package upgrades**: If upgrade policy is not `immutable`, future behavior of dependency modules is unknown. Check who holds `UpgradeCap` and what policy is set.
- **Shared object concurrent access**: Transaction ordering by validators is non-deterministic; assume worst ordering
- **Dynamic dispatch via type parameters**: Generic type `T` may be instantiated with adversarial types
- **Dependency version drift**: External package upgrades may change behavior without protocol code changes

**Workflow integration**:
- CONTESTED findings receive same verification priority as HIGH findings
- CONTESTED findings trigger production verification checkpoint (Step 4a.5)
- Cannot downgrade CONTESTED to REFUTED without production evidence

---

## Rule R5: Combinatorial Impact Analysis (adapted from EVM R5)

**For protocols managing N similar entities, analyze cumulative impact.**

When protocol manages multiple pools, vaults, markets, or objects:

**Mandatory analysis**:
1. **Single-entity impact**: What's the impact on ONE entity?
2. **N-entity cumulative**: What's N * single_impact? (check if capped by constraints)
3. **Time-compound**: What's N * impact * T? (check for accumulation over epochs)

**Sui-specific constraints**:
- **Max PTB commands**: 1024 move calls per Programmable Transaction Block
- **Max object inputs**: Limited per transaction (shared objects especially expensive due to consensus)
- **Gas budget**: Single transaction gas budget caps computation (max 50 SUI)
- **Shared object contention**: N shared objects in one PTB -> high contention cost, potential tx drops under load
- **Dynamic field iteration**: If N entities stored as dynamic fields, iteration cost scales linearly
- If N >= 10 AND processing all entities requires touching N shared objects -> check if protocol handles partial processing

**Thresholds**:
- If N >= 10 AND cumulative impact > $1,000 -> analyze further
- If N * dust > withdrawal_threshold -> flag as potential griefing vector
- If single-tx batch processing required but N > object limit -> flag as scalability risk

---

## Rule R6: Semi-Trusted Role Bidirectional Analysis (adapted from EVM R6)

**For any automated or privileged role, analyze BOTH directions.**

**Direction 1**: How can ROLE harm USERS?
- Timing attacks (Sui finality ~480ms -- fast but deterministic ordering within checkpoint)
- Parameter manipulation (choosing worst values within permitted ranges)
- Omission (failing to execute cranks, price updates, or rebalances when needed)
- Capability delegation (transferring `AdminCap` to malicious actor if it has `store`)

**Direction 2**: How can USERS exploit ROLE?
- Front-run predictable keeper actions by submitting competing transactions to validators
- Grief preconditions to block keeper's transaction from succeeding
- Force suboptimal keeper decisions by manipulating on-chain state before keeper reads it
- Exploit keeper's `TxContext` assumptions (epoch, sender address)

**Both directions are equally important. Do NOT stop at Direction 1.**

---

## Rule R7: Donation-Based DoS via Threshold Manipulation (adapted from EVM R7)

**Pattern**: Protocol has thresholds that determine operational capability
**Check**: Can donations manipulate thresholds to block operations?

**Attack vectors**:
1. **Below-threshold injection**: Drain or dilute balance below required minimum
2. **Above-threshold injection**: Push balance or count over maximum to block operations. Anyone can `transfer::public_transfer` a `Coin<T>` to any address.
3. **Dynamic field stuffing**: Add dynamic fields to shared objects (if protocol exposes add-field paths) to inflate iteration costs
4. **Counter-based gate inflation**: For every counter-based gate (e.g., `count >= minimum`), check: can entries be added that increment the counter but contribute zero/negligible value to the guarded computation? If yes, the gate passes but the computation produces a meaningless or manipulable result.

**Sui-specific vectors**:
- **Coin transfer to any address**: `transfer::public_transfer` can send `Coin<SUI>` or any `Coin<T>` to any address -- no function call on the receiving side needed
- **Object creation spam**: If protocol iterates over owned objects (via off-chain indexing), creating many small objects can degrade performance
- **Shared object congestion**: Submitting many transactions that touch a shared object can increase contention and latency for legitimate users

**Action**: For every operational threshold, check if external donations or object creation can manipulate it to cause denial of service. For every counter-based gate, check if zero-value entries can satisfy the count requirement while undermining the guarded computation's integrity.

---

## Rule R8: Cached Parameters in Multi-Step Operations (adapted from EVM R8)

**Pattern**: Operation spans multiple transactions or PTB steps with cached initial state
**Check**: Can parameters change between operation start and completion?

**Attack vectors**:
1. **Epoch staleness**: Cache epoch at start, governance changes parameters before next epoch
2. **Price staleness**: Cache oracle price, price updates before operation completes
3. **Object version staleness**: Read object state in transaction 1, object modified by another transaction before transaction 2 reads it
4. **External state staleness**: External object state (package version, capability ownership, pool parameters) validated at one entry point, stored, and relied upon at a later entry point without re-verification. The external state may change between the two calls.

**Sui-specific additions**:
- **PTB intra-transaction consistency**: Within a single PTB, earlier commands produce results consumed by later commands. If a command calls an external module that modifies shared state, subsequent commands see the updated state. However, if results are captured in local variables (MoveCall results), they represent a snapshot.
- **Cross-epoch operations**: Operations spanning epoch boundaries face parameter changes, validator set changes, and reference gas price changes.
- **Object versioning**: Sui tracks object versions. A transaction consuming an object at version V will fail if another transaction modified it to V+1 first. This provides atomic read-modify-write but means multi-step flows across transactions are NOT atomic.

**Action**: For multi-step operations (request in tx1 -> wait -> claim in tx2), for multi-step PTBs, AND for any function that stores a snapshot of external object state, verify all cached/stored state remains valid or is re-validated at each subsequent consumption point.

---

## Rule R9: Stranded Asset Severity Floor (adapted from EVM R9)

**Pattern**: Assets held by the protocol with no exit path after upgrade, migration, or state change
**Check**: Can ALL asset types the protocol holds be recovered?

**Severity floor enforcement**:
- If NO recovery path exists (no sweep, no admin rescue, no migration function) AND assets are currently held -> minimum **MEDIUM**
- If NO recovery path AND amount > $10,000 at protocol scale -> minimum **HIGH**
- If assets are theoretical only (not yet held) -> standard severity matrix applies

**Sui-specific stranding scenarios**:
- **Immutable package with no sweep**: If package is published as immutable (no `UpgradeCap`) AND has no admin withdrawal function -> assets in shared objects are permanently locked. This is IRREVERSIBLE.
- **Wrapped objects with no unwrap**: Object wrapped via `dynamic_object_field::add` or `dynamic_field::add` with no corresponding remove/unwrap function -> inner object is stranded and invisible to RPC.
- **Frozen objects**: `transfer::freeze_object` is IRREVERSIBLE. Frozen objects cannot be modified, unwrapped, or destroyed. If the frozen object holds `Balance<T>` -> permanently locked.
- **Destroyed UID with live Balance**: If a struct's `UID` is destroyed via `object::delete` while `Balance<T>` or nested objects still exist -> those assets are permanently lost.
- **Orphaned Balance<T>**: A `Balance<T>` stored in a struct with no function to withdraw or destroy it -> value locked forever.
- **Lost UpgradeCap**: If `UpgradeCap` is transferred to an inaccessible address or destroyed -> the package can never be upgraded to add recovery functions.
- **Dynamic fields on frozen objects**: Dynamic fields added to an object that is later frozen -> fields become inaccessible if no read function exists.

**Mandatory analysis for upgrade/migration protocols**:

| Step | Check | If Failed |
|------|-------|-----------|
| 1 | Inventory ALL asset types held (Coin, Balance, wrapped objects, dynamic field values) | Coverage gap |
| 2 | Does post-upgrade logic handle each asset type? | Check step 3 |
| 3 | Recovery function exists? (sweep, admin rescue, migration) | STRANDED ASSET finding |
| 4 | Apply severity floor from above | -- |

---

## Rule R10: Worst-State Severity Calibration (adapted from EVM R10)

**Pattern**: Any severity assessment that references current on-chain state
**Check**: Is the assessment using the worst REALISTIC operational state?

When assessing severity, use the WORST REALISTIC operational state, not current on-chain snapshot:

- If protocol can hold 0 to MAX tokens -> assess at realistic peak TVL
- If fee can be 0% to 100% -> assess at boundary values
- If N pools can be 1 to 1000 -> assess at realistic maximum
- If time since last action can be 0 to MAX_EPOCHS -> assess at maximum delay

**Sui-specific parameters for worst-state analysis**:
- Max gas budget per transaction: 50 SUI
- Max PTB commands: 1024
- Max input objects per transaction: ~2048
- Max transaction size: ~128KB serialized
- Epoch duration: ~24 hours
- Checkpoint interval: ~3 seconds
- Reference gas price: varies per epoch (use historical max)
- Dynamic field count: unbounded (but iteration cost scales linearly)
- Object size: max ~256KB per object

**Current on-chain state is a SNAPSHOT, not the operational envelope.**

**Action**: For every severity assessment, state the operational parameters assumed and why. Format:
```
Severity assessed at: N_pools=1000, TVL=$100M, fee=100%
Rationale: Protocol permits up to 1000 pools per documentation, fee uncapped in setter
```

---

## Rule R11: Unsolicited Object/Coin Transfer Impact (adapted from EVM R11)

**Pattern**: Protocol holds or reads `Balance<T>`, `Coin<T>`, or object state that can be modified by external transfers
**Check**: What happens if tokens or objects arrive unsolicited?

**Sui-specific vectors**:
- **Coin transfer to any address**: `transfer::public_transfer` can send `Coin<SUI>` or any `Coin<T>` to any address -- no function call on the receiving side needed, no acceptance required
- **Object transfer**: Any object with `store` ability can be transferred via `public_transfer` to any address
- **SUI gas coin merging**: Validators automatically merge gas coins; protocol logic counting coin objects may be affected
- **Shared object mutation**: If a shared object has `public` functions that accept deposits or add objects, anyone can call them

**5-Dimension Analysis** (for each external token/object type):

| Dimension | Question | Impact Pattern |
|-----------|----------|----------------|
| **Transferability** | Can this coin/object be sent to protocol-controlled addresses without calling protocol functions? | If YES -> analyze all 4 dimensions below |
| **Accounting** | Does any protocol accounting read balance or object state that changes when unsolicited assets arrive? | Inflated rewards, incorrect share prices, fee miscalculation |
| **Operation Blocking** | Does the unsolicited asset create state that blocks protocol operations? (non-zero balances preventing pool closure, unexpected objects in owned set) | DoS on admin/keeper/user functions |
| **Collection Growth** | Does the unsolicited asset create new entries in any enumerated collection? (new dynamic fields, new objects tracked by off-chain indexer) | Gas DoS via unbounded iteration |
| **Side Effects** | Does receiving this asset trigger any state changes in the protocol or external modules? | Unexpected state mutations |

**Severity floors**:
- Accounting corruption with no profitable attack -> LOW
- Operation blocking on critical functions -> minimum MEDIUM
- Gas DoS via unbounded collection growth -> minimum MEDIUM
- Profitable extraction via accounting manipulation -> standard matrix (usually HIGH)

**Action**: For every `Coin<T>` or object with `store` that the protocol interacts with, check if it can be transferred TO protocol-controlled addresses unsolicited, and trace the impact through all 5 dimensions. This includes objects returned by external module calls (LP tokens, receipt objects, reward coins) -- not just the protocol's primary token.

---

## Rule R12: Exhaustive Enabler Enumeration (adapted from EVM R12)

**Pattern**: Any finding identifies a dangerous state S that is a precondition for exploitation
**Check**: Have ALL paths to state S been enumerated?

When a finding identifies a dangerous state (e.g., "balance reaches zero", "capability transferred to attacker", "shared object in invalid state"), enumerate ALL paths to that state using these 5 actor categories:

| # | Actor Category | Sui-Specific Examples |
|---|----------------|---------------------|
| 1 | **External attacker** | Permissionless function calls on shared objects, unsolicited coin/object transfers, PTB composition attacks |
| 2 | **Semi-trusted role** | `AdminCap` holder acting within permissions but with adversarial timing or parameter choices |
| 3 | **Natural operation** | Reward accrual, user deposits/withdrawals, fee accumulation, epoch transitions |
| 4 | **External event** | Package upgrades, governance parameter changes, oracle staleness, external protocol state change |
| 5 | **User action sequence** | Normal user operations that in combination create an edge state via PTB composition |

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
1. **Who is harmed** by this design? (specific user class: depositors, LPs, borrowers, etc.)
2. **Can affected users avoid** the harm through their own actions? (or is it imposed on them?)
3. **Is the harm documented** in protocol documentation, comments, or UI? (informed consent?)
4. **Could the protocol achieve the same goal** without this harm? (alternative designs exist?)
5. **Does the function fulfill its stated purpose completely?** (e.g., an `emergency_withdraw` that only returns the primary token but not accrued rewards or wrapped objects is incomplete -- users with those asset types cannot emergency-exit)

**Verdict rules**:
- Harmed AND unavoidable AND undocumented -> FINDING (design flaw category, apply severity matrix)
- Harmed AND unavoidable AND documented -> INFO finding (users accepted known risk)
- Harmed AND avoidable -> INFO finding (user choice)
- No one harmed -> genuinely non-issue

**Sui-specific "by design" patterns to challenge**:
- "Package is immutable" -- good for trustlessness, but if a bug exists, NO fix is possible. Assess permanent impact.
- "Shared object" -- convenient for shared state, but contention risk under load. Assess degradation at peak usage.
- "Object is frozen" -- immutability is a feature, but if assets are frozen with it, they are permanently locked. Assess stranding risk.
- "Objects are owned, users control their own state" -- true, but does the protocol require users to own objects they cannot recover if lost?
- "PTBs allow composability" -- true, but does the protocol assume single-function-call semantics that PTB composition breaks?
- "One-Time Witness ensures type uniqueness" -- true at init, but are subsequent operations also type-safe?

### Passive Attack Modeling

For ANY finding involving exchange rates, multi-step timing, or parameter updates:

Model BOTH attack types:

| Attack Type | Description | Example |
|-------------|-------------|---------|
| **Active** | Attacker front-runs or back-runs a specific transaction | Sandwich attack via validator ordering, MEV on Sui |
| **Passive** | Attacker uses normal protocol functions at strategically chosen times, waiting for natural state changes | Deposit before accrual, withdraw after rate increase |
| **Design gap** | Protocol provides mechanism X for purpose Y, but X does not cover all cases Y requires | Emergency function that does not handle all asset types |

**Common passive patterns**:
- Deposit -> wait for natural reward accrual -> withdraw (timing arbitrage)
- Use normal function when parameter is at favorable boundary after epoch change
- Wait for external state change (oracle update, governance) then act within same checkpoint

**Action**: When modeling attacks, do NOT stop at "requires front-running" (active only). Always also check: "can an attacker achieve a similar result by simply timing their normal operations?" (passive).

---

## Rule R14: Cross-Variable/Object Invariant Verification (adapted from EVM R14)

**Pattern**: State spanning multiple objects or fields that MUST maintain a relationship (e.g., `pool.total_deposited == sum(receipt.amount)` across all receipt objects, `vault.share_supply == coin::total_supply(vault.treasury_cap)`)
**Check**: Can any function break the invariant?

**Methodology**:
1. For each aggregate field (total, count, sum, supply), identify ALL individual fields/objects it should track
2. For each function that modifies individual fields, verify the aggregate is updated atomically
3. For each function that modifies the aggregate directly, verify individual fields are consistent
4. Check: can the aggregate and individuals be modified through DIFFERENT code paths that desync them?
5. **Constraint coherence**: For independently-settable limits that must satisfy a mathematical relationship (e.g., `max_allocation == sum(per_pool_max)`), can one be changed without the other?
6. **Setter regression**: For each admin setter of a limit/bound/capacity -- can the new value be set BELOW already-accumulated state? If yes, check loops (infinite iteration), comparisons (bypass), arithmetic (underflow). Also check `>` vs `>=` boundary precision.

**Common invariant classes in Sui**:
- Supply invariants: `treasury_cap.total_supply == sum(all coin.value)` -- enforced by Sui runtime, but custom tokens may have wrapper accounting
- Balance invariants: `pool.total_balance == sum(user_receipt.amount)` across all receipt objects
- Count invariants: `registry.pool_count == dynamic_field count of pool entries`
- Wrapped object invariants: objects wrapped in dynamic fields must maintain parent-child consistency
- Constraint coherence: `global_cap >= sum(per_pool_caps)`, `max_leverage >= min_collateral_ratio`

**Sui-specific**: State is spread across OBJECTS, not just variables within a contract. Cross-object invariants (e.g., `pool.total == sum(receipt_i.value)` across all user receipt objects) are especially hard to enforce because different users own different receipt objects. The protocol can only verify its own shared/owned objects atomically -- user-owned receipt objects are checked only when presented to the protocol.

**Action**: For every aggregate/total field, trace ALL modification paths for both the aggregate AND its components. If any path modifies one without the other -> FINDING. For every admin setter of a limit/bound, verify it cannot regress below accumulated state.

---

## Rule R15: Flash Loan / PTB Precondition Manipulation (adapted from EVM R15)

**Pattern**: Any function precondition that depends on state manipulable within a single Programmable Transaction Block
**Check**: Can the precondition be satisfied/bypassed atomically within a single PTB?

**Sui key difference**: PTBs are the NATIVE composition mechanism. No special flash loan protocol is needed -- any lending module's borrow() + repay() can be composed in a single PTB. This makes atomic manipulation a FIRST-CLASS concern on Sui.

| State Type | Manipulation Method | PTB Accessible? | Check |
|-----------|-------------------|:---------------:|-------|
| `balance::value` | Deposit / `coin::split` + supply to pool | YES (0 cost within PTB) | Can inflated balance bypass checks? |
| Oracle price | Trade on source pool within PTB | YES (slippage cost) | Is spot used instead of TWAP? |
| Threshold / quorum | Deposit / stake within PTB | YES | Can threshold be crossed atomically? |
| Exchange rate | Deposit to inflate shares | YES | Does rate affect minting/redemption? |
| Collateral ratio | Add collateral within PTB | YES | Can temporary collateral enable actions? |
| Object ownership | Transfer object in earlier PTB command | YES | Can ownership precondition be faked? |
| Shared object state | Call public mutation function | YES | Can object state be manipulated then restored? |

**Hot potato enforcement**: The hot potato pattern (struct with no `drop`/`store`/`copy`/`key`) enforces repayment within the same PTB. If correctly implemented, the receipt MUST be consumed. BUT: the BORROWED FUNDS can still be used for manipulation within the PTB -- hot potato only ensures repayment, not that the loan wasn't used for exploitation.

Verify hot potato correctness:
1. Receipt struct has NO abilities (no `copy`, `drop`, `store`, `key`)
2. Receipt cannot be wrapped inside an object with `store`
3. Consumption function validates amount + fee + source
4. Abort during consumption -> entire PTB reverts (safe -- loan never disbursed)

**Mandatory sequence modeling**: For each PTB-accessible state, model the full atomic sequence:
1. BORROW (from lending module) -> 2. MANIPULATE state -> 3. CALL target function -> 4. EXTRACT value -> 5. RESTORE state -> 6. REPAY (consume hot potato)
7. Compute: profit = extracted_value - borrow_fee - gas. If profit > 0 -> FINDING.

**Action**: For every function with a balance/oracle/threshold/rate/ownership precondition, check if PTB composition can satisfy it atomically. See FLASH_LOAN_INTERACTION skill for full methodology.

---

## Rule R16: Oracle Integrity -- Sui Adaptation (adapted from EVM R16)

**Pattern**: Any module logic that consumes oracle data for decisions
**Check**: Is the oracle data validated for all failure modes?

| Check | Pyth on Sui | Switchboard on Sui | Supra on Sui | Custom Oracle |
|-------|------------|-------------------|--------------|---------------|
| Staleness | `price_info.timestamp` checked against max age | `aggregator.latest_timestamp` checked | `price_data.timestamp` checked | Custom -- check freshness field |
| Confidence | `price.conf` vs `price.price` ratio | `result.confidence_interval` | Varies | Custom |
| Price > 0 | `price.price > 0` validated | `result > 0` | Same | Must validate |
| Exponent/Decimals | `price.exponent` (negative, e.g., -8) handled | Decimals from feed config | Decimals handling | Must match consumer |
| Feed object verification | Validate `PriceInfoObject` ID against known constant | Validate aggregator object ID | Validate feed ID | Validate source |
| Freshness | Price updated within same PTB via `pyth::update_price` | Feed updated recently | Same | Must ensure freshness |
| TWAP window | If using time-weighted price: window vs liquidity | N/A | N/A | Custom |
| Fallback | What happens if oracle module aborts? | What happens if Switchboard aborts? | Same | Must have fallback |
| Config bounds | Oracle config setters (max age, deviation, staleness) have meaningful min/max | Same | Same | Same |

**Pyth on Sui specifics**: Pyth uses a pull model -- the price must be updated within the same PTB (or very recently) by calling `pyth::update_price` with a verified VAA. Check: (1) what if the Pyth update command is omitted from the PTB? (2) what if an old VAA is replayed? (3) is `max_age` parameter enforced?

**Action**: For every oracle data consumption point, verify ALL applicable checks from the table above. Missing checks -> FINDING at severity based on impact. See ORACLE_ANALYSIS skill for full methodology.
- For every oracle configuration setter (window size, max deviation, heartbeat), check: can the parameter be set to a value that effectively disables the oracle validation? If yes -> FINDING (Rule 14 setter regression applies).

---

## Rule R17: State Transition Completeness

**Pattern**: Operations with symmetric branches -- profit/loss, deposit/withdraw, mint/burn, stake/unstake, increase/decrease
**Check**: All state fields modified in one branch are either (a) also modified in the other branch, or (b) explicitly documented as intentionally asymmetric.

**Methodology**:
1. For each pair of symmetric operations, list ALL state fields modified by the "positive" branch (profit, deposit, mint, stake, increase)
2. For the "negative" branch (loss, withdraw, burn, unstake, decrease), verify each field from step 1 is also handled
3. If a field is missing from the negative branch: trace what happens to dependent computations when that field retains its old value while other fields changed
4. Flag branch size asymmetry > 3x in code volume (lines of code) as a review trigger -- large asymmetry often indicates incomplete handling

**Common miss patterns**:
- Profit branch updates `locked_profit` + `total_value` + `high_water_mark`, loss branch updates only `total_value` -> `locked_profit` can exceed `total_value` -> underflow
- Deposit updates `total_deposited` + mints shares, emergency withdraw burns shares but doesn't update `total_deposited` -> accounting desync
- Stake updates `total_staked` + `last_stake_epoch`, unstake updates `total_staked` but not `last_stake_epoch` -> stale time-dependent calculations

**Sui-specific**: State may be spread across multiple objects (shared pool object, user receipt objects, admin config objects, dynamic fields). Ensure ALL objects updated in the positive branch are also updated in the negative branch. Pay special attention to:
- **Dynamic fields**: Positive branch adds/modifies a dynamic field -> negative branch must handle that field
- **Wrapped objects**: Positive branch wraps an object into another -> negative branch must unwrap or account for it
- **Events**: Positive branch emits events -> negative branch should emit corresponding events for indexer consistency

**Action**: For every operation pair, produce a field-by-field comparison table. Missing fields in the negative branch that have dependent consumers -> FINDING.

---

## Rule MR1: Ability Analysis (Shared Move Rule)

**Pattern**: Every struct definition with ability annotations
**Check**: Are the assigned abilities security-appropriate?

| Ability | What It Allows in Sui | Security Risk If Misapplied |
|---------|----------------------|----------------------------|
| `copy` | Value can be duplicated | Token/receipt duplication -- value tokens MUST NOT have `copy` |
| `drop` | Value can be silently discarded | Obligation bypass -- hot potatoes (flash loan receipts, permission tokens) MUST NOT have `drop` |
| `store` | Value can be stored in other objects AND transferred via `transfer::public_transfer` | Unrestricted transferability -- access control tokens with `store` can be transferred to unauthorized parties |
| `key` | Value is a Sui object (must have `id: UID` as first field) | Object identity -- required for on-chain existence. `key` without `store` restricts transfer to defining module only |

**Critical patterns**:

| Pattern | Abilities at Risk | Impact | Check |
|---------|------------------|--------|-------|
| Hot potato (flash loan receipt) | `drop` must be ABSENT | If `drop` present -> receipt discarded -> loan not repaid | Verify zero abilities on receipt struct |
| Capability object (AdminCap) | `store` enables `public_transfer` | If `store` present -> anyone holding cap can transfer it away | `key` only -> module-controlled transfer |
| Value-bearing struct | `copy` must be ABSENT | If `copy` present -> struct duplicated -> double-spend | Verify no `copy` on value structs |
| One-Time Witness (OTW) | Must have `drop` only | OTW pattern: struct named after module, `drop` only, no fields | Verify OTW has exactly `drop`, consumed in `init()` |
| Phantom type parameter | `phantom T` not checked at runtime | Malicious `T` can be supplied if not constrained | Verify `T` is validated in function logic |
| Key-only transfer control | `key` without `store` | Transfer controlled by defining module -- adding `store` = lose transfer control | Verify intentional if `store` added to `key` struct |

**Mandatory checks**:
1. **Value tokens** (`Coin<T>`, custom tokens representing value): MUST NOT have `copy`. Must have `drop` only if zero-value destruction is safe.
2. **Capability/authority structs** (`AdminCap`, `TreasuryCap`): `key` required. Should NOT have `store` unless intentional transferability is desired. MUST NOT have `copy` or `drop`.
3. **Hot potato structs** (flash loan receipts, sequencing tokens): MUST have NO abilities -- all four absent. This forces consumption within the same PTB.
4. **Receipt/proof structs**: Assess whether `drop` is safe -- if dropping the receipt skips a finalization step, `drop` is dangerous.
5. **Witness types** (One-Time Witness): Must have `drop` only. MUST NOT have `copy`, `store`, or `key`. Must be consumed in `init` function.

**Action**: For every struct, verify its abilities match its security requirements. Mismatched abilities -> FINDING. Document ability-to-purpose mapping.

---

## Rule MR2: Bit-Shift Overflow Safety (Shared Move Rule)

**Pattern**: Any use of `<<` or `>>` operators
**Check**: Shift amount validated against bit width BEFORE the shift operation

**CRITICAL**: Move does NOT check shift amounts at runtime. Left shift by >= bit_width SILENTLY produces 0. This was the root cause of the $223M Cetus hack on Sui.

**Mandatory checks**:

| Check | What to Verify | Impact if Missing |
|-------|---------------|-------------------|
| Shift amount < bit_width | `shift_amount < 64` for `u64`, `shift_amount < 128` for `u128`, `shift_amount < 256` for `u256` | Silent zero result -> catastrophic arithmetic error |
| Pre-shift overflow | `value << amount` won't overflow the type | Value silently truncated |
| Right shift underflow | `value >> amount` behavior at boundaries | May produce 0 when non-zero expected |
| Dynamic shift amount | Shift amount derived from user input or computation | Attacker controls shift amount -> controls output |

**Attack example** (Cetus-style):
```move
// VULNERABLE: no validation on shift_amount
let result = 1u128 << shift_amount; // if shift_amount >= 128, result = 0
let price = numerator / result;     // division by zero or infinite price
```

```move
// SAFE: bounded before use
assert!(shift_amount < 128, E_INVALID_SHIFT);
let result = 1u128 << shift_amount;
```

**Action**: For every `<<` and `>>` operation, trace the shift amount to its source. If unbounded or derived from user input/computation without explicit bounds checking -> FINDING. This is a non-negotiable requirement -- the Cetus exploit proved this can cause hundreds of millions in losses.

---

## Rule MR3: Type Safety and Generic Parameters (Shared Move Rule)

**Pattern**: Generic type parameters in functions and structs
**Check**: Are type parameters sufficiently constrained? Can adversarial type instantiation cause harm?

| Attack Vector | Description | Sui-Specific Defense |
|--------------|-------------|---------------------|
| Phantom type spoofing | `Coin<FakeUSDC>` passed as `Coin<USDC>` | Type system prevents at compile time for known types; runtime: use `type_name::get<T>()` for dynamic validation |
| Generic pool confusion | `Pool<A, B>` vs `Pool<B, A>` (swapped type params) | Verify type parameter ordering is validated or canonicalized |
| Witness pattern bypass | Module witness `W` not properly constrained | One-Time Witness (OTW) must be consumed on use; verify `types::is_one_time_witness<T>()` |
| Dynamic type confusion | Dynamic field read with wrong type parameter | `dynamic_field::borrow<K, V>()` -- wrong `V` type -> deserialization failure or wrong data |
| `type_name` comparison | String-based type comparison may be incomplete | Ensure full path comparison including package ID, not just module::name |
| Unconstrained generics | Functions accepting `<T>` without ability bounds | May accept unexpected types; functions accepting `<T: store + drop>` may accept types with unintended behavior |
| Type confusion in collections | Dynamic fields keyed by type (`dynamic_field::add<TypeKey<T>, Value>`) | Can different `T` instantiations collide or overwrite each other? |

**Action**: For every generic type parameter, verify constraints are sufficient to prevent adversarial instantiation. For every OTW, verify it is consumed in `init` and cannot be stored or replicated. For dynamic fields, verify type parameters match across add/borrow/remove calls.

---

## Rule MR4: Dependency and Package Version Analysis (Shared Move Rule)

**Pattern**: External package dependencies declared in `Move.toml`
**Check**: Are dependencies pinned, upgrade-safe, and version-consistent?

**Checks**:
1. **Dependency inventory**: List all `[dependencies]` in `Move.toml` with their source (git, local, published address)
2. **Version pinning**: Are dependencies pinned to specific revisions/addresses? Unpinned git dependencies can change between builds.
3. **Upgrade policy of dependencies**: If a dependency package has an active `UpgradeCap`, its behavior can change. The audited protocol's security depends on the dependency's immutability.
4. **Transitive dependencies**: Dependencies of dependencies -- are they also secure?
5. **Function visibility of consumed APIs**: Does the protocol use `public` functions that the dependency could remove in an upgrade?

**Upgrade policy risk levels**:

| Policy | Risk | Implication |
|--------|------|-------------|
| `immutable` | LOW | Cannot be changed -- fully trustless |
| `dep_only` | LOW | Can only change dependencies, not code |
| `additive` | MEDIUM | Can add new functions, cannot modify existing |
| `compatible` | HIGH | Can modify implementations while keeping signatures |

**Action**: For every external dependency, assess upgrade risk and document. If protocol security depends on immutable behavior of an upgradeable dependency -> FINDING.

---

## Rule MR5: Visibility and Access Control (Shared Move Rule)

**Pattern**: Every function declaration
**Check**: Are functions exposed at the correct visibility level?

| Visibility | Who Can Call | Composable in PTB? | Security Implication |
|-----------|------------|:------------------:|---------------------|
| `public` | Any module in any package | YES (via move call) | Maximum exposure -- cannot be revoked even in upgrades. Widest attack surface. |
| `public(package)` | Any module in the SAME package | YES (from same package) | Package-internal -- safe for inter-module helpers |
| `entry` | Only callable as PTB command (not by other Move functions) | NO (standalone only, cannot be composed with other move calls) | Transaction-level only -- prevents module-to-module composition |
| `fun` (private) | Only within the defining module | NO | Minimum exposure |

**Critical visibility mistakes**:

| Mistake | Problem | Impact |
|---------|---------|--------|
| `public` on state-changing function intended as `entry` | Function composable in PTB via other modules -> PTB manipulation attacks | Attacker chains manipulate->exploit->restore in one PTB |
| `public` on internal helper | Helper exposed to external packages | Unintended state mutations by external callers |
| `entry` on function meant for composability | Cannot be called by other modules or within PTB chains | Integration failure, protocol unusable by aggregators |
| `public(package)` on function needing external access | External packages cannot integrate | Protocol isolation |
| Missing access control on `public` function mutating shared object | Anyone can call with `&mut SharedObject` | Unauthorized state changes |
| `public` function lock-in | `public` functions CANNOT be removed or have signatures changed in upgrades | Functions that may need modification should use `public(package)` or `entry` |
| `friend` deprecation | Legacy code using `friend` declarations | Sui Move deprecated `friend` in favor of `public(package)` |

**Action**: For every function, verify visibility matches intent. For every `public` function that modifies shared object state, verify access control (capability check, or explicit design for permissionless access). For every state-modifying function, verify visibility is minimized.

---

## Rule SR1: Object Ownership Model Security (Sui-Specific)

**Pattern**: Objects created, transferred, shared, frozen, or wrapped by the protocol
**Check**: Is the ownership model appropriate for each object's security requirements?

| Ownership | Properties | Security Implications |
|-----------|-----------|----------------------|
| **Owned** | Single owner, no contention, fast path (no consensus) | Only owner can use in transaction; safe from external mutation; but owner can refuse to present (griefing shared protocols); lost if owner address compromised |
| **Shared** | Anyone can reference in transaction (with write access via `&mut`) | Concurrent access, ordering attacks, no access control by default -- ANY `public` function accepting `&mut SharedObj` is callable by anyone |
| **Frozen/Immutable** | Anyone can read (`&SharedObj`), nobody can modify | Safe for constants and configs; but CANNOT be updated even by admin; IRREVERSIBLE -- assess stranding risk |
| **Wrapped** | Inside another object, UID not exposed to RPC | Parent controls all access; invisible to RPC queries; must be unwrapped to use; can cause user confusion |
| **Dynamic field object** | Object stored as dynamic field of parent | Has own UID but accessed through parent; parent access control determines who can read/mutate |

**Security checks**:

| # | Check | What to Verify | Impact if Wrong |
|---|-------|---------------|----------------|
| 1 | Shared object exposure | Is the object shared when it should be owned? | Shared = widest attack surface; every `public` function taking `&mut` is permissionless |
| 2 | Owned->Shared irreversibility | `transfer::public_share_object` is ONE-WAY and IRREVERSIBLE | Owned object shared by mistake cannot be un-shared; capability shared = capability leaked forever |
| 3 | Frozen irreversibility | `transfer::freeze_object` is IRREVERSIBLE | Assets inside frozen object permanently locked; config in frozen object can never be updated |
| 4 | Wrapped object visibility | Wrapped objects not visible to RPC queries | Users cannot query wrapped objects; debugging harder; user-impacting consequences? |
| 5 | Dynamic field access | Objects stored as dynamic fields accessed through parent | Parent access control governs -- verify parent's `public` functions don't expose dynamic field objects to unauthorized parties |
| 6 | Capability object ownership | Is AdminCap/UpgradeCap owned, shared, or wrapped? | Owned = single admin; shared = anyone with `public` function access; wrapped = parent controls |
| 7 | Transfer restrictions | Objects with `key` but no `store` -- transfer controlled by defining module | Verify restriction is intentional and sufficient |
| 8 | Dynamic fields on transferable objects | Dynamic fields travel with parent on transfer | If protocol attaches important state as dynamic fields to user-owned objects, that state moves when user transfers the parent |

**Action**: For every object the protocol creates, verify ownership model matches security requirements. Flag any capability object that is shared. Flag any irreversible ownership transition (share, freeze) that lacks explicit confirmation/guard. Mismatched ownership -> FINDING.

---

## Rule SR2: Programmable Transaction Block (PTB) Composability Security (Sui-Specific)

**Pattern**: Protocol functions that can be composed in PTBs (all `public` functions)
**Check**: Can PTB composition create attack vectors?

PTBs allow up to 1024 move calls in a single atomic transaction. This creates attack vectors unique to Sui:

| # | Check | Attack Pattern | Defense |
|---|-------|---------------|---------|
| 1 | Atomic manipulation | manipulate() -> exploit() -> restore() in one PTB (flash-loan-equivalent without needing a lending protocol) | Use `entry` for sensitive state changes; or add invariant checks that validate state consistency post-call |
| 2 | Return value routing | PTB routes return value from call A as input to call B, bypassing intended access patterns | Verify return types don't grant unintended capabilities; use hot potato pattern for forced consumption |
| 3 | Shared object multi-mutation | Multiple PTB steps mutate the same shared object -- invariants may hold per-call but break across the sequence | Add epoch/version guards; or validate cross-call invariants in each function entry |
| 4 | Entry vs public analysis | `entry` functions are standalone (cannot compose with other move calls); `public` functions CAN compose | State-changing functions that should be isolated -> `entry`; composable building blocks -> `public` |
| 5 | Hot potato across PTB steps | Hot potato struct passed between PTB move call steps | Hot potato with zero abilities MUST be consumed within same PTB (enforced by type system -- cannot store or drop). Verify abilities are correct. |
| 6 | Object consumption ordering | PTB steps can consume objects in unexpected order | Verify protocol doesn't depend on specific ordering of object consumption across PTB steps |
| 7 | Single-call assumption | Protocol designed assuming each user action is a separate transaction | PTB allows multiple "actions" atomically, bypassing cooldowns or rate limits |
| 8 | Mixed module calls | PTB can call functions from different modules/packages in a single atomic transaction | Combining behaviors from different modules in unintended ways |

**Action**: For every `public` and `entry` function, analyze what happens when called in combination with other protocol functions within a single PTB. For every `public` function that mutates shared state, model whether a PTB can compose it with other calls to create an atomic manipulation sequence. For sensitive state changes, evaluate whether `entry` visibility would be more appropriate. Unintended compositions -> FINDING.

---

## Rule SR3: Package Version and Upgrade Safety (Sui-Specific)

**Pattern**: Published Sui packages with upgrade capabilities
**Check**: Does the protocol's security depend on specific package versions? Can upgrades break invariants?

Sui packages have explicit upgrade policies controlled by `UpgradeCap`:

| Policy | What's Allowed | Security Implication |
|--------|---------------|---------------------|
| **compatible** | Add functions, add abilities to generics, change implementations | Most flexible; risk of behavior change; admin trust required |
| **additive** | Only add new functions and types; existing code frozen | Safer -- existing logic immutable; only new functionality added |
| **dependency-only** | Only update dependency versions | Very restricted -- only dep patches flow through |
| **immutable** | Nothing -- permanently locked | Fully trustless; but no bug fixes possible ever |

**Security checks**:

| # | Check | What to Verify | Impact if Wrong |
|---|-------|---------------|----------------|
| 1 | UpgradeCap security | Who holds the `UpgradeCap`? Is it in a shared object accessible to unauthorized parties? | If shared/leaked -> unauthorized package upgrades possible |
| 2 | Type confusion across versions | Package v1 creates objects with type layout A; v2 changes compatible behavior. Do existing v1 objects work correctly with v2 functions? | Field misinterpretation, accounting errors on pre-upgrade objects |
| 3 | Cross-package version consistency | If protocol spans multiple packages, are all packages compatible after a partial upgrade? | Package A v2 calls Package B v1 -> interface mismatch or stale behavior |
| 4 | Upgrade policy matches risk | DeFi protocol holding $100M with `compatible` upgrade -> high admin trust required | Should policy be more restrictive? Does governance structure justify the policy? |
| 5 | UpgradeCap destruction | Has the UpgradeCap been destroyed to make the package immutable? Was this intentional? | If destroyed accidentally -> can never fix bugs; if preserved unnecessarily -> trust vector remains |
| 6 | Policy downgrade | `UpgradeTicket` creation restricts future upgrades -- policy can only become MORE restrictive | Verify protocol hasn't accidentally restricted itself from needed future upgrades |
| 7 | `public` function lock-in | `public` functions cannot be removed or have signatures changed in upgrades | Are there `public` functions the developer may want to modify later? |
| 8 | Shared object compatibility | After upgrade, existing shared objects still reference old code | New transactions use new code, but objects created by old code may not be compatible |

**Action**: Assess upgrade risk for the protocol and all its dependencies. If protocol security depends on immutable behavior of an upgradeable package -> FINDING. If `UpgradeCap` is stored insecurely -> FINDING. For every upgradeable package, identify: (1) UpgradeCap holder, (2) current upgrade policy, (3) existing objects that may be affected by future upgrades.

---

## Rule SR4: Hot Potato and Capability Pattern Security (Sui-Specific)

**Pattern**: Zero-ability structs used for enforcement (flash loan receipts, action tickets) and capability objects used for authorization
**Check**: Can the enforcement/authorization be bypassed?

### Hot Potato Pattern

Hot potato is a struct with NO abilities that forces callers to return it within the same transaction:

```move
struct FlashLoanReceipt { amount: u64, fee: u64 }
// No abilities (no copy, drop, store, key)
// MUST be consumed by repay() within same PTB
// Cannot be stored, dropped, copied, or transferred
```

| # | Check | What to Verify | Impact if Wrong |
|---|-------|---------------|----------------|
| 1 | Zero abilities | Hot potato struct has NO abilities (especially no `drop`) | `drop` -> receipt discarded -> loan not repaid |
| 2 | Consumption validates | `repay()` function checks: correct amount + fee, correct pool, not double-consumed | Under-repayment, wrong pool, replay |
| 3 | No wrapping bypass | Can the receipt be placed inside an object with `store`? | If possible -> store receipt -> take loan without repaying in same tx |
| 4 | Abort safety | If consuming function aborts, transaction rolls back -- ALL state including the loan is reversed | This is SAFE in Move -- abort = full rollback. No risk of loan-taken-but-not-repaid via abort. |
| 5 | Multiple receipts | Can multiple receipts be obtained and only some repaid? | Track receipt count or use unique IDs |
| 6 | Nested hot potatoes | If a hot potato contains or references another hot potato | Verify nesting does not create deadlock or bypass |

### Capability Objects

| # | Check | What to Verify | Impact if Wrong |
|---|-------|---------------|----------------|
| 1 | Ability audit | Does the capability have `store`? If yes -> transferable by anyone via `public_transfer` | Capability leak -- unintended transfer to attacker |
| 2 | Uniqueness | Is there exactly one capability object of this type? (use OTW pattern for singleton guarantees) | Multiple caps -> multiple admins, or cap duplication attack |
| 3 | Ownership model | Is the cap owned (single admin), shared (multi-access), or wrapped (parent-controlled)? | Shared cap -> any `public` function accepting it is admin-callable by anyone |
| 4 | Revocation | Can the capability be revoked/destroyed? By whom? | If no revocation -> compromised cap is permanent |
| 5 | Delegation | Can the cap be used to create sub-capabilities? Are sub-caps properly scoped? | Over-broad delegation -> privilege escalation |
| 6 | Creation paths | Enumerate ALL functions that create capabilities | Can capabilities be created outside `init()`? If yes, is that intentional? |

**Common hot potato patterns**:
- Flash loan receipts: `FlashLoanReceipt { amount: u64, fee: u64 }` -- consumed by `repay()` which verifies `amount + fee` is returned
- Permission tokens: `ActionPermission { action_type: u8 }` -- consumed by the permitted action function
- Sequencing tokens: `StepOneComplete { data: ... }` -- consumed by step two function

**Action**: For every hot potato struct, verify all 6 checks. If any consumption path allows value extraction without meeting obligations -> FINDING (typically HIGH or CRITICAL). For every capability object, audit abilities, uniqueness, ownership, revocation, and creation paths.

---

## Evidence Source Tags -- Sui Move

| Tag | Description | Valid for REFUTED? |
|-----|-------------|-------------------|
| [PROD-ONCHAIN] | Read from production Sui object on-chain | YES |
| [PROD-SOURCE] | Verified source from Sui Explorer / published package | YES |
| [PROD-FORK] | Tested on local Sui node with mainnet state dump | YES |
| [CODE] | From audited codebase source | YES |
| [MOCK] | From mock/test setup | **NO** |
| [EXT-UNV] | External, unverified | **NO** |
| [DOC] | From documentation only | **NO** |

**Any REFUTED verdict where ALL external behavior evidence is tagged [MOCK], [EXT-UNV], or [DOC] is automatically escalated to CONTESTED.** Only [PROD-ONCHAIN], [PROD-SOURCE], [PROD-FORK], and [CODE] evidence can support REFUTED for external module behavior.

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

[MOCK], [EXT-UNV], and [DOC] evidence CANNOT support a REFUTED verdict for findings involving external package behavior. Only [PROD-ONCHAIN], [PROD-SOURCE], [PROD-FORK], or [CODE] evidence (direct source reading of the external package) qualifies.
