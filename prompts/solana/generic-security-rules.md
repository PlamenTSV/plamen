# Generic Security Rules - Solana

> **Usage**: Analysis agents and depth agents reference these rules during Solana program analysis.
> These rules cover ALL Solana programs regardless of type. Rules R1-R16 are adapted from EVM equivalents. Rules S1-S10 are Solana-specific.

---

## Rule R1: CPI Return and Account Reload Validation (adapted from EVM R1)

**Pattern**: Any CPI call that modifies accounts or returns data
**Check**: After CPI, are all affected accounts reloaded? Do returned/modified values match expectations?

| Mismatch Type | Example | Impact |
|---------------|---------|--------|
| Stale account data post-CPI | Token balance not reloaded after CPI transfer | Accounting uses pre-CPI balance |
| Account owner changed via CPI | CPI target calls `assign` | Program reads account now owned by attacker |
| Mint mismatch | Expected Token mint, got Token-2022 mint with extensions | Transfer fees unaccounted, permanent delegate risk |
| Token-2022 extension awareness | Program treats Token-2022 mint as basic SPL Token | Missing transfer fee deduction, hook revert |

**Action**: For every CPI call, verify: (1) accounts modified by the target are reloaded, (2) account owners are re-checked post-CPI, (3) mint type (Token vs Token-2022) is validated before any token operation.

---

## Rule R2: Instruction Preconditions Are Griefable (adapted from EVM R2)

**Pattern**: Any instruction with preconditions based on externally-manipulable state
**Check**: Can external actors manipulate state to make the precondition fail or succeed at the wrong time?

This includes:
- Crank/keeper instructions with balance-dependent preconditions
- Permissionless instructions with oracle-dependent preconditions
- Any instruction reading token account balances that can be donated to

**Direction 2 - Admin action impacts on user functions**: For every admin instruction that modifies a parameter used in user-facing instruction preconditions:
- Can an admin parameter change make a user instruction behave unexpectedly?
- Does the admin change retroactively affect users in active positions?

**Solana-specific vectors**:
- **PDA creation front-running**: Attacker creates the PDA before the legitimate initialization
- **Account creation griefing**: Attacker creates ATA or account before user, controlling initial state
- **SOL dust donation**: Send lamports to any account to prevent garbage collection or inflate balance checks

**Action**: For every instruction with a precondition, identify whether the precondition state can be manipulated by: (1) direct user action (deposit/withdraw/transfer), (2) instruction composition in same tx, (3) SOL/token donation (unsolicited transfers), (4) PDA front-running.

---

## Rule R3: Transfer Side Effects (adapted from EVM R3)

**Pattern**: Any SPL Token transfer or CPI that moves tokens
**Check**: Does the transfer trigger side effects?

| Token Type | Side Effect | Check |
|-----------|------------|-------|
| Basic SPL Token | None (safe) | No side effects |
| Token-2022 with TransferHook | Hook program executes on every transfer | CU budget, revert risk, state changes |
| Token-2022 with TransferFee | Fee deducted from transfer amount | Net amount ≠ gross amount |
| Token-2022 with PermanentDelegate | Delegate can transfer without approval | Vault drain risk |
| CPI target returning tokens | Target program may modify additional state | Account reload required |

**Mandatory check**: For every token the protocol handles:
- [ ] Is it basic SPL Token or Token-2022?
- [ ] If Token-2022: what extensions are active?
- [ ] Does transfer trigger hook execution?
- [ ] Does transfer deduct fees?
- [ ] Can a permanent delegate move tokens without protocol consent?

---

## Rule R4: Uncertainty Handling - Adversarial Assumption 
**CONTESTED is a TRIGGER, not a TERMINAL state.**

When marking any finding as CONTESTED:
1. **Enumerate** all plausible external behaviors
2. **Assess** severity for each scenario
3. **Escalate** if ANY scenario results in HIGH/CRITICAL
4. **Default** to WORST-CASE severity until production behavior verified

**Solana-specific uncertainty sources**:
- **Upgradeable programs**: Unknown future behavior if upgrade authority is active
- **Account substitution**: Unknown accounts passed as remaining_accounts
- **CPI targets**: Target program behavior may change if upgradeable

---

## Rule R5: Combinatorial Impact Analysis (adapted from EVM R5)

**Pattern**: Protocol manages N similar entities (vaults, pools, markets, etc.)
**Check**: Cumulative impact across all entities + CU limit constraints

**Solana-specific**: Batch operations across N entities may exceed the 200K CU transaction limit. Check:
- If N ≥ 10: does processing all entities fit in one transaction?
- If not: is the protocol designed for partial processing? What's the impact of partial-only?
- N × dust > withdrawal_threshold → griefing vector

---

## Rule R6: Semi-Trusted Role Bidirectional Analysis 
For any automated role (cranks, bots, operators):

**Direction 1**: How can ROLE harm USERS?
- Timing attacks (400ms slot time on Solana - much faster than EVM)
- Parameter manipulation
- Omission (failing to crank when needed)

**Direction 2**: How can USERS exploit ROLE?
- Front-run predictable crank actions
- Grief preconditions to block crank
- Force suboptimal crank decisions

---

## Rule R7: Donation-Based DoS via Balance Manipulation (adapted from EVM R7)

**Pattern**: Protocol has thresholds that determine operational capability
**Check**: Can donations manipulate thresholds to block operations?

**Solana-specific vectors**:
- **SOL lamport donation**: Send SOL directly to any account (no function call needed)
- **Token account balance inflation**: Transfer SPL tokens to vault's token account
- **PDA creation front-running**: Create PDA before intended initialization to block it
- **Counter-based gate inflation**: Zero-value entries passing count-based gates without contributing economic value

---

## Rule R8: Cached Parameters in Multi-Step Operations (adapted from EVM R8)

**Pattern**: Operation spans multiple transactions with cached initial state
**Check**: Can parameters change between operation start and completion?

**Solana-specific additions**:
- **Intra-transaction CPI staleness**: Account data cached by instruction 1, modified by CPI in instruction 2, read stale by instruction 3 - all in same transaction
- **Slot-based timing**: Parameters keyed to slot numbers vs wall clock time
- **Cross-instruction staleness**: Multiple instructions in same tx share account state; CPI in earlier instruction changes state that later instruction reads stale
- **Cross-transaction external state**: External account state (ownership, delegation, program status) read and stored in one transaction, relied upon in a later transaction without re-checking the account

**Action**: For multi-step operations AND multi-instruction transactions AND any instruction that stores a snapshot of external account state, verify all cached/stored state remains valid or is re-validated at each subsequent consumption point.

---

## Rule R9: Stranded Asset Severity Floor 
**Pattern**: Assets held by the program with no exit path
**Check**: Can ALL asset types be recovered?

**Solana-specific stranding scenarios**:
- **Program immutability**: If program is not upgradeable AND has no sweep function → assets permanently stranded
- **Token account ownership lock**: Token account owned by PDA of non-upgradeable program with no transfer instruction → tokens locked forever
- **Closed account lamports**: Lamports from account closure not fully recovered

**Severity floor**: No recovery path → minimum MEDIUM. No recovery AND amount > $10,000 → minimum HIGH.

---

## Rule R10: Worst-State Severity Calibration 
**Solana-specific parameters for worst-state analysis**:
- Max accounts per transaction: 64 (v1) / 256 (Address Lookup Tables)
- CU budget: 200,000 default / 1,400,000 max per transaction
- Max account data size: 10MB (after realloc)
- Peak account count for the protocol
- Slot time: ~400ms

---

## Rule R11: Unsolicited Token/SOL Transfer Impact (adapted from EVM R11)

**Pattern**: Protocol reads token account balances or SOL balances
**Check**: What happens if tokens/SOL arrive unsolicited?

**Solana-specific vectors**:
- **SOL lamport transfer**: Anyone can send SOL to any account (no function call needed)
- **SPL Token transfer**: Anyone can transfer SPL tokens to any token account they know the address of
- **ATA creation**: Anyone can create an Associated Token Account for any wallet/mint combination

**5-Dimension Analysis** (Solana-adapted):
1. **Transferability**: Can tokens/SOL be sent without calling program functions?
2. **Accounting**: Does protocol read `token_account.amount` or `account.lamports` directly?
3. **Operation Blocking**: Does unsolicited balance prevent operations?
4. **Collection Growth**: Does the transfer create new entries in iterated collections?
5. **Side Effects**: Does receiving trigger state changes in other programs?

---

## Rule R12: Exhaustive Enabler Enumeration 
For EACH dangerous precondition state, fill the 5-actor-category table. Solana-specific paths per category:
1. **External attacker**: Permissionless instruction calls, unsolicited token/SOL transfers, ATA creation
2. **Semi-trusted role**: Crank/bot acting within permissions but with adversarial timing
3. **Natural operation**: Reward accrual, user deposits/withdrawals, epoch changes
4. **External event**: Program upgrade, governance parameter change, oracle staleness
5. **User action sequence**: Normal usage creating edge states via instruction composition

---

## Rule R13: User Impact Evaluation - Anti-Normalization 
5-question test for any finding marked "by design":
1. **Who is harmed** by this design gap?
2. **Can affected users avoid** the harm?
3. **Is the gap documented** in protocol docs?
4. **Could the protocol achieve the same goal** without this gap?
5. **Does the instruction fulfill its stated purpose completely?**

**Solana-specific "by design" patterns to challenge**:
- "Users must pay rent for accounts" - true, but does the protocol unnecessarily burden users with account creation costs?
- "CU limits prevent this" - true in current version, but CU limits change; assess if protocol degrades gracefully
- "Program is upgradeable, admin can fix it" - upgradeability itself is a trust assumption; assess admin risk

---

## Rule R14: Cross-Variable/Account Invariant Verification (adapted from EVM R14)

**Pattern**: State spanning multiple accounts that must maintain a relationship
**Check**: Can any instruction break the invariant?

**Solana-specific**: State is spread across ACCOUNTS, not just variables. Cross-account invariants (e.g., `pool.total_deposited == sum(user_account.deposited)` across all user PDAs) are harder to enforce atomically.

**Constraint coherence**: For independently-settable limits that have a required relationship, verify the relationship is enforced on-chain. If limit A and limit B can desync → what breaks?
**Setter regression**: For admin setters of limits/bounds, check: can the new value be set below accumulated state? E.g., `set_max_stake(new_max)` where `new_max < current_total_staked` → undefined behavior for existing stakers.

---

## Rule R15: Flash Loan / Instruction Composition Precondition Manipulation (adapted from EVM R15)

**Pattern**: Any instruction precondition that depends on state manipulable within a single transaction
**Check**: Can the precondition be satisfied/bypassed via instruction composition?

**Solana difference**: No callback model. Instead, multiple instructions composed in a single transaction achieve the same effect:
1. Instruction 1: Borrow from lending protocol
2. Instruction 2: Manipulate target protocol state
3. Instruction 3: Extract value from target
4. Instruction 4: Repay lending protocol

**Any lending protocol on Solana is a potential flash loan source** - no special flash loan interface needed.

**Action**: For every instruction with a balance/oracle/threshold precondition, check if instruction composition within one transaction can satisfy it atomically.

---

## Rule R16: Oracle Integrity - Solana Adaptation (adapted from EVM R16)

**Pattern**: Any program logic that consumes oracle data
**Check**: Is the oracle data validated for all failure modes?

| Check | Pyth-Specific | Switchboard-Specific | Chainlink-Specific |
|-------|--------------|---------------------|-------------------|
| Staleness | `price.publish_time` + `conf_interval` | `aggregator.latest_confirmed_round.round_open_timestamp` | Similar to EVM |
| Confidence | `price.conf` vs `price.price` ratio | `result.confidence_interval` | N/A |
| Price > 0 | `price.price > 0` | `result > 0` | Same |
| Exponent handling | `price.exponent` (negative, e.g., -8) | Decimals from feed config | Same |
| Feed account verification | Validate price feed pubkey against known constant | Validate aggregator pubkey | Same |
| Status check | `price.status == Trading` | Aggregator not stale | N/A |
| TWAP window | If using EMA price: window length vs liquidity | N/A | N/A |
| Fallback | What happens if Pyth program reverts? | What happens if Switchboard reverts? | Same |

**Pyth pull model**: Price must be updated within the same transaction (or recently) - adds instruction to tx. Check: what if the Pyth update instruction is omitted?

---

## Rule S1: Account Validation Completeness (Solana-Specific)

**Pattern**: Every instruction handler receives accounts
**Check**: Is EVERY account fully validated (owner + type + data + constraints)?

**Mandatory checks per account type**:

| Account Type | Owner Check | Type Check | Data Validation | Anchor Auto? |
|-------------|-----------|----------|----------------|-------------|
| `Account<T>` | ✓ (auto) | ✓ (discriminator auto) | Constraints needed | Partial |
| `UncheckedAccount` | ✗ (manual needed) | ✗ (manual needed) | ✗ (manual needed) | NO |
| `AccountInfo` | ✗ (manual needed) | ✗ (manual needed) | ✗ (manual needed) | NO |
| `SystemAccount` | ✓ (system program) | ✓ | N/A | YES |
| `Signer` | ✗ (only checks is_signer) | ✗ | ✗ | Partial |
| `Program` | ✓ (executable check) | N/A | N/A | YES |

**Action**: For every `UncheckedAccount`, `AccountInfo`, and `Signer` in every instruction, verify manual validation exists.

---

## Rule S2: PDA Security

**Pattern**: Program Derived Addresses used for authority, state storage, or account derivation
**Check**: Canonical bumps, seed collision prevention, seed uniqueness

**Checks**:
1. **Canonical bump**: All PDAs use `find_program_address` or Anchor's `bump` constraint (never user-supplied bump)
2. **Seed collision**: No two PDA seed schemas can produce the same byte sequence
3. **Seed uniqueness**: User-specific PDAs include user pubkey in seeds
4. **PDA sharing**: Multiple account types don't share the same seed schema
5. **Init front-running**: `init` used (not `init_if_needed`) for security-critical PDAs

---

## Rule S3: CPI Security

**Pattern**: Cross-Program Invocations (invoke/invoke_signed/CpiContext)
**Check**: Target validation, signer propagation, account reload, lamport conservation

**Checks**:
1. **Target program ID**: Validated against hardcoded constant (not from user input)
2. **Signer privilege**: User wallet not forwarded to untrusted CPI targets
3. **Account reload**: All accounts modified by CPI target are `reload()`'d before subsequent use
4. **Owner re-check**: Account owner verified unchanged after CPI (defend against `assign`)
5. **Lamport conservation**: SOL balance checked before/after CPI for unexpected drains
6. **CPI depth**: Nested CPI chains don't approach the 4-level depth limit

---

## Rule S4: Account Closing and Revival Prevention

**Pattern**: Account close operations
**Check**: Complete closing (4 steps) + revival attack prevention

**4 closing steps** (ALL required):
1. Zero all account data
2. Transfer ALL lamports to recipient
3. Set discriminator to CLOSED sentinel
4. Transfer ownership to system program

**Revival attack**: Within same transaction, attacker re-funds a closed account with lamports, making it exist again with zeroed data. Prevention requires checking discriminator, not just data length.

---

## Rule S5: Stale Account Data After CPI

**Pattern**: Any instruction that reads account data after a CPI call
**Check**: Is `reload()` called before subsequent reads?

**CRITICAL**: This is the #1 most common Solana vulnerability pattern.
- Anchor caches account data at instruction start
- CPI modifies the actual account data on-chain
- Without `reload()`, the instruction reads stale cached data
- **Note**: `reload()` refreshes data but does NOT re-check owner

---

## Rule S6: Remaining Accounts Injection

**Pattern**: Any use of `ctx.remaining_accounts`
**Check**: Manual validation of every remaining account

`remaining_accounts` bypass ALL Anchor automatic validation. For each remaining account, manually verify:
- Owner (is it the expected program?)
- Type (discriminator check)
- Signer status (if required)
- Data validity (constraints, relationships)
- Key uniqueness (not duplicating a named account)

---

## Rule S7: Duplicate Mutable Account Attack

**Pattern**: Instructions accepting 2+ mutable accounts
**Check**: Key uniqueness constraints

**Attack**: Pass the same account as both `from` and `to` parameters. Effects:
- Self-transfer inflation (credit + debit to same account = net positive if implementation has ordering bugs)
- Double-counting in accounting logic
- Bypassing balance checks (check balance of A, debit from A, credit to A=same account)

**Defense**: `require!(account_a.key() != account_b.key())` for all mutable account pairs.

---

## Rule S8: Sysvar and System Account Spoofing

**Pattern**: Sysvar access via account input (not `Sysvar::get()`)
**Check**: Address validated against known sysvar address

**Attack pattern (sysvar address spoofing)**: If Instructions sysvar passed as generic AccountInfo without address validation, attacker passes a fake account → reads attacker-crafted data as instruction history.

**Defense**:
- Use `Sysvar::from_account_info()` (validates address)
- Or explicit `require!(account.key() == sysvar::instructions::ID)`
- Use `Clock::get()` instead of passing Clock as account where possible

---

## Rule S9: Token-2022 Extension Awareness

**Pattern**: Protocol interacts with SPL Token mints that may be Token-2022
**Check**: Extension handling for all relevant extensions

**Critical extensions**:
- **PermanentDelegate**: Can drain ANY token account of that mint - vault risk
- **TransferHook**: Executes arbitrary code on every transfer - CU budget, revert risk
- **TransferFee**: Fee deducted from transfer amount - accounting mismatch
- **CPI Guard**: Blocks delegated transfers via CPI - integration failure
- **MintCloseAuthority**: Mint can be closed - reading zeroed mint data
- **DefaultAccountState**: New accounts start frozen - initialization failure

**Action**: For every mint the program interacts with, verify extension handling.

---

## Rule S10: Instruction Introspection Security

**Pattern**: Transaction instruction introspection for flash loan guards or atomic checks
**Check**: Sysvar validation, checked functions, sequence completeness

**Checks**:
1. Instructions sysvar address validated (not spoofable)
2. `load_instruction_at_checked` used (not deprecated `load_instruction_at`)
3. Instruction sequence validated completely (no gaps where attacker can insert)
4. Program ID of inspected instructions verified (not just function signature match)
5. State changes between checked instructions accounted for

---

## Rule S11: Zero Copy Struct Layout Verification

**Pattern**: Any account using `#[account(zero_copy(unsafe))]` with `#[repr(C)]`
**Check**: Explicit padding, alignment correctness, total size match

Solana zero_copy accounts bypass Borsh serialization and map directly to memory. `repr(C)` uses C-style layout with alignment requirements - implicit padding can cause:
- UB if Anchor reads memory at wrong offsets
- Data corruption if field alignment assumptions are wrong
- Account size mismatch if INIT_SPACE doesn't account for padding

**Mandatory checks for each zero_copy struct**:

| Check | What to Verify | How |
|-------|---------------|-----|
| Explicit padding | Every gap between fields has a `_paddingN: [u8; N]` field | Sum field sizes + padding = total without implicit gaps |
| Alignment | Each field starts at offset divisible by its alignment (u64 → 8, u32 → 4, u16 → 2, Pubkey → 1, bool → 1) | Walk struct field by field, compute offsets |
| Total size | `size_of::<Struct>()` matches INIT_SPACE annotation (if present) or `space` in `#[account(init, space = N)]` | Compare computed size vs declared space |
| Padding arithmetic | `_paddingN` size is correct for the gap | After a `bool` (1 byte) before a `u64` (8-byte aligned), padding should be 7 bytes, not 6 or 8 |

**Action**: For every `#[account(zero_copy(unsafe))]` struct, walk the field layout computing offsets and verify all 4 checks. An off-by-one in padding = potential memory corruption.

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
- Profit branch updates `locked_profit` + `total_value` + `high_water_mark`, loss branch updates only `total_value` → `locked_profit` can exceed `total_value` → underflow
- Deposit updates `total_deposited` + mints shares, emergency withdraw burns shares but doesn't update `total_deposited` → accounting desync
- Stake updates `total_staked` + `last_stake_time`, unstake updates `total_staked` but not `last_stake_time` → stale time-dependent calculations

**Solana-specific**: State may be spread across multiple accounts (vault PDA, strategy PDA, receipt PDA). Ensure ALL accounts updated in the positive branch are also updated in the negative branch.

**Action**: For every operation pair, produce a field-by-field comparison table. Missing fields in the negative branch that have dependent consumers → FINDING.

---

## Evidence Source Tags - Solana

| Tag | Description | Valid for REFUTED? |
|-----|-------------|-------------------|
| [PROD-ONCHAIN] | Read from production Solana account on-chain | YES |
| [PROD-SOURCE] | Verified source from Solana Explorer / anchor verify | YES |
| [PROD-LITESVM] | Tested on LiteSVM with mainnet account dumps | YES |
| [CODE] | From audited codebase source | YES |
| [MOCK] | From mock/test setup | **NO** |
| [EXT-UNV] | External, unverified | **NO** |
| [DOC] | From documentation only | **NO** |

---

## Enforcement Mechanisms

### Devil's Advocate FORCING
"could/might" language → MUST pursue to conclusion. Hedged language is a signal that analysis is incomplete. Replace with a definitive YES/NO after tracing the path.

### CONTESTED Triggers Production Fetch
CONTESTED findings require production verification via Helius MCP tools or CLI. A finding that remains CONTESTED without production data is a coverage gap.

### REFUTED Priority Chain Analysis
Chain analyzer must search ALL findings for enablers before accepting REFUTED. A REFUTED finding may become PARTIAL or CONFIRMED when another finding creates its missing precondition.

### Cross-Validation Before REFUTED
REFUTED verdict requires state evidence (on-chain data, source code proof). If state evidence is unavailable → verdict is CONTESTED, not REFUTED.

### Evidence Source Enforcement
[MOCK], [EXT-UNV], and [DOC] evidence CANNOT support a REFUTED verdict for findings involving external program behavior. Only [PROD-ONCHAIN], [PROD-SOURCE], [PROD-FORK], or [CODE] evidence (direct source reading of the external program) qualifies.
