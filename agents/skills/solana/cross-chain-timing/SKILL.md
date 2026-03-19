---
name: "cross-chain-timing"
description: "Trigger Pattern wormhole|allbridge|debridge|bridge|cross_chain|vaa|guardian|emitter|LayerZero|CCIP|nonce.sequence|relay - Inject Into Breadth agents, depth-external"
---

# CROSS_CHAIN_TIMING Skill (Solana)

> **Trigger Pattern**: `wormhole|allbridge|debridge|bridge|cross_chain|vaa|guardian|emitter|LayerZero|CCIP|nonce.*sequence|relay`
> **Inject Into**: Breadth agents, depth-external
> **Finding prefix**: `[CCT-N]`
> **Rules referenced**: R1, R2, R4, R8, R10, R16

Covers: cross-chain message verification, timing asymmetry between Solana and other chains, account creation requirements, nonce/sequence replay protection, and cross-chain price relay staleness.

Solana's fast finality (~400ms optimistic, ~30s confirmed/rooted) creates a fundamental timing asymmetry with slower chains (Ethereum ~12min, rollups 10-60min). This asymmetry is the primary attack vector for cross-chain timing exploits on Solana.

---

## Step 1: Identify Cross-Chain Messaging Infrastructure

Find all cross-chain messaging calls and infrastructure:

| # | Bridge/Protocol | Direction | Solana Instruction | Remote Chain | Message Type |
|---|----------------|-----------|-------------------|-------------|-------------|
| 1 | {Wormhole/Allbridge/deBridge/custom} | {Solana->Remote / Remote->Solana} | {instruction name} | {Ethereum/Arbitrum/etc.} | {token transfer / state sync / price relay / governance} |

### Wormhole-Specific Inventory
If Wormhole is detected:

| Component | Instruction/Account | Purpose | Location |
|-----------|-------------------|---------|----------|
| VAA Verification | `verify_signatures` + `post_vaa` | Guardian signature verification | {file:line} |
| Message Posting | `post_message` | Send message from Solana | {file:line} |
| Token Bridge | `complete_transfer` / `create_wrapped` | Token bridging | {file:line} |
| Emitter Account | PDA (emitter seeds) | Message source identity | {file:line} |

### Allbridge/deBridge-Specific Inventory
If Allbridge or deBridge detected:

| Component | Account/Instruction | Verification Method | Location |
|-----------|-------------------|-------------------|----------|
| Message Account | {account type} | {signature/merkle/optimistic} | {file:line} |
| Relayer | {relayer constraint} | {how relayer is validated} | {file:line} |
| Nonce Tracking | {nonce account} | {replay prevention method} | {file:line} |

---

## Step 2: Cross-Chain Message Verification Audit

For EACH inbound cross-chain message consumed by the program:

### 2a. Wormhole VAA Verification Checklist

| # | Check | Status | Location | Notes |
|---|-------|--------|----------|-------|
| 1 | Guardian signature count >= quorum (13/19) | YES/NO | {line} | Check: does protocol verify `vaa.guardian_set_index` is current? |
| 2 | Guardian set is current (not expired) | YES/NO | {line} | Old guardian sets may be compromised |
| 3 | Emitter chain ID validated | YES/NO | {line} | Reject messages from unexpected source chains |
| 4 | Emitter address validated | YES/NO | {line} | Reject messages from unexpected contracts on source chain |
| 5 | Sequence number replay check | YES/NO | {line} | Each VAA sequence should be processed exactly once |
| 6 | Consistency level validated | YES/NO | {line} | `finalized` vs `confirmed` - determines security guarantee |
| 7 | Payload format validated | YES/NO | {line} | Malformed payload handling |
| 8 | VAA account owner is Wormhole program | YES/NO | {line} | Prevents fake VAA account substitution |

**Critical**: Missing checks 1-5 = **CRITICAL** (arbitrary cross-chain message injection). Missing checks 6-8 = **HIGH** (message quality/integrity issues).

### 2b. Generic Bridge Verification

For non-Wormhole bridges:

| # | Check | Status | Location | Notes |
|---|-------|--------|----------|-------|
| 1 | Message source authenticated (signatures/proofs) | YES/NO | {line} | |
| 2 | Source chain ID validated | YES/NO | {line} | |
| 3 | Source contract/address validated | YES/NO | {line} | |
| 4 | Replay protection (nonce/sequence/bitmap) | YES/NO | {line} | |
| 5 | Message freshness (timestamp/block check) | YES/NO | {line} | |
| 6 | Relayer authorization (if applicable) | YES/NO | {line} | |

---

## Step 3: Timing Window Analysis

### 3a. Finality Asymmetry Model

| Chain | Optimistic Finality | Confirmed Finality | Protocol Assumes |
|-------|--------------------|--------------------|-----------------|
| Solana | ~400ms (processed) | ~30s (rooted/finalized) | {which level?} |
| {Remote Chain} | {time} | {time} | {which level?} |
| **Asymmetry Window** | - | - | **{max delay between chains}** |

**Critical question**: When Solana processes a message about remote chain state, how old can that state be? Compute: `max_staleness = remote_finality + bridge_relay_delay + solana_processing_time`

### 3b. Stale State Usage Trace

For each piece of state synced cross-chain:

| State Variable | Source Chain | Sync Trigger | Max Staleness | Solana Functions Using It | Fresh Required? |
|----------------|-------------|-------------|--------------|--------------------------|----------------|
| {state} | {chain} | {event/periodic/manual} | {time estimate} | {list instructions} | YES/NO |

For each dependent instruction on Solana:
- Is fresh state required or is stale acceptable?
- What decisions are made with potentially stale data?
- Can an attacker exploit the staleness window?

### 3c. Solana-to-Remote Timing Attack

Solana's fast finality means actions on Solana are visible almost immediately, but take time to propagate to remote chains:

```
1. Attacker acts on Solana (visible in ~400ms)
2. Solana message posted via bridge (begins relay)
3. TIMING WINDOW: Remote chain does not yet know about Solana action
4. Attacker acts on remote chain using pre-Solana-action state
5. Bridge message arrives on remote chain - state updates
6. Attacker profited from acting on both chains during asymmetry
```

### 3d. Remote-to-Solana Timing Attack

```
1. State changes on remote chain (e.g., price moves, governance action)
2. Bridge message relay begins (latency: {estimate})
3. TIMING WINDOW: Solana still uses old remote state
4. Attacker acts on Solana using stale remote state
5. Bridge message arrives on Solana - state updates
6. Attacker profited from Solana action with stale state
```

---

## Step 4: Account Creation Requirements

Cross-chain operations on Solana have unique account requirements:

| # | Check | Status | Notes |
|---|-------|--------|-------|
| 1 | Recipient token account exists (ATA) before transfer arrival? | YES/NO | If NO: who creates it? Who pays rent? |
| 2 | `init_if_needed` used for receiver accounts? | YES/NO | If YES: check for re-initialization risk |
| 3 | What happens if recipient account does not exist? | {revert/skip/queue} | Reverted transfers may be lost |
| 4 | Can attacker close recipient ATA before message arrives? | YES/NO | Token account close + re-create with different owner |
| 5 | Are PDAs used for cross-chain escrow? | YES/NO | Check PDA seed uniqueness per message |
| 6 | Is there a recovery mechanism for failed deliveries? | YES/NO | Lost funds if no recovery |

**Critical Solana pattern**: Cross-chain token transfers require the destination ATA to exist. If it does not:
- Some bridges revert and the tokens are stuck on the source chain
- Some bridges create the ATA (who pays rent-exempt minimum?)
- Some bridges queue the transfer for later claim (is the queue unbounded?)

---

## Step 5: Nonce and Sequence Management

| # | Check | Status | Location | Notes |
|---|-------|--------|----------|-------|
| 1 | Replay protection exists | YES/NO | {line} | Method: {bitmap/counter/hash set/PDA per message} |
| 2 | Replay check is BEFORE state changes | YES/NO | {line} | If after: partial replay possible |
| 3 | Out-of-order messages handled | YES/NO | {line} | Strict ordering vs any-order processing |
| 4 | Sequence gaps handled | YES/NO | {line} | What if message N+1 arrives before N? |
| 5 | Nonce account sized for growth | YES/NO | {line} | Bitmap may run out of space |
| 6 | Double-spend across chains | YES/NO | {line} | Same asset spent on both chains during relay |

**Solana replay patterns**:
- **PDA per message**: Derive PDA from message hash/sequence. If PDA exists, already processed. Reliable but creates many accounts.
- **Bitmap account**: Store processed sequences as bits. Space-efficient but must handle bitmap growth.
- **Counter**: Only process sequence N if N-1 was processed. Enforces ordering but blocks on gaps.

---

## Step 6: Cross-Chain Price Relay Audit

If oracle prices are relayed cross-chain:

| # | Check | Status | Notes |
|---|-------|--------|-------|
| 1 | Price freshness validated on Solana side | YES/NO | Max acceptable age? |
| 2 | Price source authenticated | YES/NO | Can fake price be relayed? |
| 3 | Price deviation bounds | YES/NO | Max delta from last known price? |
| 4 | Fallback if relay is delayed/offline | YES/NO | What happens to price-dependent operations? |
| 5 | Flash loan on source chain can manipulate relayed price | YES/NO | Is source chain price spot or TWAP? |

**Staleness calculation**: `relay_staleness = source_price_age + bridge_latency + solana_processing`

If `relay_staleness > acceptable_threshold` at worst case, price is stale. Apply Rule 16 (Oracle Integrity).

---

## Step 7: Quantify Arbitrage Viability

```
1. Attacker monitors {SOURCE_CHAIN} for state changes at {MONITOR_POINT}
2. State change triggers sync message (latency window opens: {LATENCY_ESTIMATE})
3. Attacker executes on Solana at {EXPLOIT_INSTRUCTION} using stale {STALE_STATE}
4. Sync message arrives, state updates on Solana
5. Profit = {PROFIT_FORMULA}
6. Cost = bridge_fees + Solana_tx_fees + capital_lockup_cost + Jito_tip
7. Viable if: profit > cost AND repeatable
```

**Solana cost model**: Solana transaction fees are very low (~5000 lamports base + priority fee). The primary cost is capital lockup and bridge fees, not gas. This makes small-margin attacks more viable on Solana than EVM.

---

## Key Questions (must answer all)

1. What is the realistic sync latency for {BRIDGE_PROTOCOL}? (cite documentation)
2. Can an attacker monitor the remote chain and front-run sync on Solana? (Solana's low fees make this cheap)
3. What is the maximum state change during normal operation within the sync window?
4. Is this attack repeatable or one-time?
5. Are recipient accounts pre-created, or must they be created on arrival?
6. Is replay protection complete (covers all message types, all chains)?
7. Can an attacker exploit Solana's fast finality to act before the remote chain sees Solana state?
8. Are cross-chain prices validated for freshness AND deviation bounds?

---

## Common False Positives

- **Monotonic state**: If synced state only increases, arbitrage may not be profitable in both directions
- **Negligible delta**: If max delta during sync window is <0.1%, may not be economically viable after bridge fees
- **Rate limiting**: If operations have cooldowns longer than sync latency, window may not be exploitable
- **Confirmed finality enforcement**: If protocol requires rooted/finalized Solana confirmations before processing, timing window is ~30s (larger but more reliable)
- **Bridge-level protections**: Some bridges (Wormhole) have rate limiting or value caps that bound exploitation

---

## Instantiation Parameters
```
{CONTRACTS}           - Programs to analyze
{BRIDGE_PROTOCOL}     - Specific bridge (Wormhole, Allbridge, deBridge, custom)
{SYNC_POINT}          - Instruction where cross-chain state is consumed
{DEPENDENT_FUNCTIONS} - Instructions that read synced state
{SOURCE_CHAIN}        - Chain where state originates
{MONITOR_POINT}       - What attacker monitors on source chain
{EXPLOIT_INSTRUCTION} - Instruction attacker calls on Solana
{STALE_STATE}         - Specific state that becomes stale
{LATENCY_ESTIMATE}    - Realistic bridge latency
```

---

## Output Schema

| Field | Required | Description |
|-------|----------|-------------|
| bridge_inventory | yes | All cross-chain messaging infrastructure |
| verification_audit | yes | VAA/message verification completeness |
| timing_windows | yes | Asymmetry windows with duration estimates |
| account_creation | yes | Recipient account requirements and failure modes |
| replay_protection | yes | Nonce/sequence management assessment |
| price_relay_audit | if applicable | Cross-chain price freshness and manipulation risk |
| arbitrage_viability | yes | Quantified attack profitability or NOT_VIABLE |
| finding | yes | CONFIRMED / REFUTED / CONTESTED |
| evidence | yes | Code locations with line numbers |
| step_execution | yes | Status for each step |

---

## Step Execution Checklist (MANDATORY)

| Step | Required | Completed? | Notes |
|------|----------|------------|-------|
| 1. Identify Cross-Chain Messaging Infrastructure | YES | | |
| 2. Cross-Chain Message Verification Audit | YES | | |
| 3. Timing Window Analysis (both directions) | YES | | |
| 4. Account Creation Requirements | YES | | |
| 5. Nonce and Sequence Management | YES | | |
| 6. Cross-Chain Price Relay Audit | IF price relay detected | | |
| 7. Quantify Arbitrage Viability | YES | | |

### Cross-Reference Markers

**After Step 2**: If VAA verification is incomplete -> immediate finding, do not wait for timing analysis.

**After Step 3**: Feed timing windows to TEMPORAL_PARAMETER_STALENESS skill for parameters cached across chain boundaries.

**After Step 4**: If account creation can fail -> cross-reference with ACCOUNT_LIFECYCLE skill for stranded asset analysis (Rule 9).

**After Step 6**: Feed price staleness findings to ORACLE_ANALYSIS (Solana version) if applicable.
