---
name: "cross-chain-message-integrity"
description: "Type Thought-template (instantiate before use) - Trigger Pattern CROSS_CHAIN_MSG flag detected (protocol RECEIVES cross-chain messages)"
---

# Skill: Cross-Chain Message Integrity

> **Type**: Thought-template (instantiate before use)
> **Trigger Pattern**: CROSS_CHAIN_MSG flag detected (protocol RECEIVES cross-chain messages)
> **Inject Into**: Breadth agents, depth-external
> **Finding prefix**: `[CMI-N]`
> **Rules referenced**: R1, R2, R4, R8, R10

Covers: message endpoint authentication, peer/remote verification, replay protection, payload validation, and message ordering for bridge-receiving protocols.

This skill is SEPARATE from CROSS_CHAIN_TIMING (which covers stale state and latency arbitrage for L2 interactions). Use this skill when the protocol RECEIVES and PROCESSES inbound cross-chain messages. Use CROSS_CHAIN_TIMING when the protocol READS state synced across chains.

---

## Trigger Patterns
```
lzReceive|_ccipReceive|receiveWormholeMessages|onOFTReceived|
setPeer|setTrustedRemote|_nonblockingLzReceive|executeMessage|
_processMessageFrom|ILayerZeroReceiver|IAny2EVMMessageReceiver|
endpoint.*receive|bridge.*receive|relayer.*deliver|_lzReceive
```

---

## Step 1: Message Receiving Surface Inventory

For each function that processes inbound cross-chain messages:

| # | Function | Bridge Protocol | Source Auth? | Payload Validated? | State Modified | Access Control |
|---|----------|----------------|-------------|-------------------|----------------|---------------|

For each entry:
- What bridge/messaging protocol delivers the message?
- Can the function be called DIRECTLY by anyone, or only via the bridge endpoint?
- What state does the function modify based on message content? (mint, unlock, update, execute)

---

## Step 2: Endpoint Authentication Audit

For EACH message-receiving function:

### 2a. Caller Verification
| # | Check | Status | Location |
|---|-------|--------|----------|
| 1 | `msg.sender == endpoint/router` verified | YES/NO | {line} |
| 2 | Endpoint address immutable or admin-protected | YES/NO | {line} |
| 3 | Modifier checks the CORRECT address variable | YES/NO | {line} |

**Missing caller check → CRITICAL**: Anyone can fabricate message data and trigger mints/unlocks.

### 2b. Source Origin Verification
| # | Check | Status | Location |
|---|-------|--------|----------|
| 1 | Source chain ID validated against allowed set | YES/NO | {line} |
| 2 | Source sender validated against registered peer | YES/NO | {line} |
| 3 | BOTH checks present (chain AND sender) | YES/NO | {line} |

**Pattern**: Checks `_origin.srcEid` (chain) but not `_origin.sender` (peer) → accepts messages from ANY contract on allowed chains.

---

## Step 3: Peer Registry Security

For each function that configures trusted peers/remotes:

### 3a. Setter Access Control
| # | Check | Status | Location |
|---|-------|--------|----------|
| 1 | Access-controlled (onlyOwner/multisig/timelock) | YES/NO | {line} |
| 2 | Validates new peer is non-zero | YES/NO | {line} |
| 3 | Emits event for off-chain monitoring | YES/NO | {line} |
| 4 | Timelock/delay on peer changes | YES/NO | {line} |

### 3b. Peer Binding Completeness
- Peer mapping keyed by chain ID? One peer per chain, or multiple?
- Can in-flight messages from OLD peer be processed after peer change?
- Default state for unregistered chain: does `_origin.sender == peers[chainId]` pass when BOTH are zero?

### 3c. Cross-Chain Address Assumptions
- Does the protocol assume `address(X) on Chain A == address(X) on Chain B` means same owner?
- For CREATE-deployed contracts: different deployer nonce across chains → same address, different owner.
- For EOAs: private key owner is the same across chains (safe). For contracts: NOT guaranteed.

Tag: `[TRACE:setPeer(chain={X}) → access={check} → zero_check={YES/NO} → default_peer={value}]`

---

## Step 4: Replay Protection

### 4a. Message Uniqueness
| # | Check | Status | Location |
|---|-------|--------|----------|
| 1 | Each message processed exactly once | YES/NO | {line} |
| 2 | Replay check BEFORE state changes | YES/NO | {line} |
| 3 | Out-of-order messages handled | YES/NO | {line} |
| 4 | Sequence gaps handled gracefully | YES/NO | {line} |

### 4b. Cross-Chain Replay
- Message valid on chain A replayable on chain B?
- Payload includes destination chain ID AND destination address?
- Same contract deployed on N chains: message for chain A processable on chain B?

### 4c. Re-org Safety
- Source chain re-org: can previously-processed message be re-delivered with different nonce?
- Protocol responsibility vs bridge responsibility for re-org handling?

Tag: `[TRACE:message_nonce={N} → replay_check={method} → before_state_change={YES/NO}]`

---

## Step 5: Payload Validation

### 5a. Format Enforcement
- Payload decoded with explicit type checks? (`abi.decode` with expected types)
- Malformed payload handling: revert, silent skip, or partial decode?
- Payload length mismatch: can it cause incorrect ABI decoding of dynamic types?

### 5b. Value Bounds
For each decoded value:
- Bounds checks present? (amount ≤ supply cap, address ≠ zero, deadline not expired)
- Can source chain send payload causing overflow/underflow when processed?
- Addresses decoded from payload: treated as address on THIS chain or source chain?

### 5c. Arbitrary Execution
If message triggers execution of decoded calldata:
- Target restricted to known contracts?
- Function selector restricted to safe set?
- Can decoded calldata invoke `transferFrom`/`approve` on tokens the contract holds or has approvals for?

Tag: `[BOUNDARY:payload_amount={MAX} → decoded → processed_as={result}]`

---

## Step 6: Message Ordering and Delivery

### 6a. Ordering Dependencies
- Any messages depend on previous messages being processed first?
- Out-of-order arrival: state corruption or graceful handling?
- Queue/retry mechanism for failed deliveries?

### 6b. Blocked Message Recovery
- Failed message: retryable? By whom? With what gas limit?
- Permanently blocked message prevents subsequent messages? (head-of-line blocking)
- Admin mechanism to skip/clear blocked messages?
- Can attacker intentionally cause failure to block the queue?

Tag: `[TRACE:message_N_fails → message_N+1={blocked/processed} → recovery={mechanism}]`

---

## Key Questions (must answer all)
1. Can any receiving function be called directly without going through the bridge endpoint?
2. Are BOTH source chain AND source address validated against registered peers?
3. What is the default behavior for messages from an UNREGISTERED chain/peer?
4. Is each message processed exactly once with replay check BEFORE state changes?
5. Can decoded payload values cause overflow, underflow, or arbitrary execution?
6. What happens when delivery fails or messages arrive out of order?

## Common False Positives
- **Bridge-level replay**: Bridge protocol itself prevents replay AND protocol correctly verifies bridge auth → protocol-level replay may be unnecessary
- **Idempotent operations**: Protocol allows re-delivery by design (same result regardless of count) → not a replay vulnerability
- **Admin peer with timelock**: `setPeer` behind multisig + timelock → low unauthorized change risk
- **View-only consumption**: Message updates state also validated by other mechanisms (oracle bounds, rate limits) → bounded impact

## Instantiation Parameters
```
{CONTRACTS}           -- Contracts with message receiving functions
{BRIDGE_PROTOCOL}     -- Bridge/messaging protocol (LayerZero, CCIP, Wormhole, Axelar, Hyperlane)
{RECEIVE_FUNCTIONS}   -- Functions that process inbound messages
{PEER_SETTERS}        -- Functions that configure trusted peers/remotes
{STATE_MODIFIED}      -- State modified by message processing
```

## Step Execution Checklist (MANDATORY)

| Step | Required | Completed? | Notes |
|------|----------|------------|-------|
| 1. Message Receiving Surface Inventory | YES | | All receiving functions |
| 2. Endpoint Authentication Audit | YES | | Caller + source origin |
| 3. Peer Registry Security | IF configurable peers | | Setter access, binding, defaults |
| 4. Replay Protection | YES | | Uniqueness, cross-chain, re-org |
| 5. Payload Validation | YES | | Format, bounds, arbitrary execution |
| 6. Message Ordering and Delivery | IF ordered messages | | Dependencies, blocked recovery |
