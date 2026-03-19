---
name: "governance-attack-vectors"
description: "Protocol Type Trigger governance (detected when Governor, Timelock, voting, proposal, quorum, delegate patterns found) - Inject Into Breadth agents, depth-external, depth-edge-case"
---

# Injectable Skill: Governance Attack Vectors

> **Protocol Type Trigger**: `governance` (detected when Governor, Timelock, voting, proposal, quorum, delegate patterns found)
> **Inject Into**: Breadth agents, depth-external, depth-edge-case
> **Language**: EVM only (Solana has structural mitigations via token locking; Move governance is less standardized)
> **Finding prefix**: `[GOV-N]`

## Orchestrator Decomposition Guide
When decomposing this skill into depth agent investigation questions, map sections to domains:
- Section 1: depth-external (flash loan voting, external token interactions)
- Section 2: depth-state-trace (proposal lifecycle state, execution integrity)
- Section 3: depth-edge-case (quorum boundaries, threshold edge cases)
- Section 4: depth-state-trace (delegation state, vote counting)

## When This Skill Activates

Recon detects governance patterns: `Governor`, `TimelockController`, `propose`, `castVote`, `execute`, `queue`, `quorum`, `getVotes`, `delegate`, `votingPower`, or DAO framework imports.

---

## 1. Flash Loan Voting Analysis

### 1a. Vote Power Source
Identify how voting power is determined:
- Snapshot-based (block number checkpoint) or live balance?
- If snapshot: when is the snapshot taken? (proposal creation, vote start, or fixed intervals)
- If live balance: can voting power be acquired via flash loan within the voting transaction?

### 1b. Snapshot Manipulation Window
If snapshot-based:
- Is there a delay between proposal creation and snapshot? (proposal → delay → snapshot → voting)
- Can an attacker acquire tokens BEFORE snapshot and return them AFTER? (multi-block attack)
- Is the snapshot block predictable? Can attacker front-run to accumulate tokens in the snapshot block?

### 1c. Delegation Flash Attack
For delegation-based voting:
- Can delegation be changed within the same block as voting?
- Pattern: flash borrow tokens → delegate to self → vote → undelegate → return tokens (single tx if no snapshot or snapshot is current block)
- Is `delegate()` subject to the same snapshot as `getVotes()`?

Tag: `[TRACE:vote_power_source={snapshot/live} → snapshot_block={when} → flash_window={YES/NO}]`

---

## 2. Proposal Lifecycle Security

### 2a. Proposal Creation
- What is the minimum threshold to create a proposal? (token balance, delegation threshold)
- Can proposal threshold be met via flash loan? (same flash analysis as voting)
- Is there a limit on active proposals? (unbounded proposals → storage/gas griefing)
- Can an attacker spam proposals to dilute voter attention or exhaust gas budgets?

### 2b. Proposal Content Validation
For each proposal that includes executable calldata:
- Is the target contract restricted? (whitelist vs arbitrary address)
- Is the function selector restricted? (whitelist vs arbitrary calldata)
- Can a proposal encode calls to the governance contract itself? (self-referential governance: change quorum, change timelock, change voting period)
- Can a proposal encode calls to the token contract? (mint tokens, change supply, modify balances)

### 2c. Execution Integrity
For the execution path (typically via timelock):
- Is there a mandatory delay between queue and execution?
- Can the delay be bypassed? (emergency execute, guardian role, zero-delay configuration)
- Can a queued proposal be re-executed? (replay of governance action)
- Is execution atomic? If one action in a batch fails, do all revert?

### 2d. Cancellation and Veto
- Who can cancel a proposal? (proposer, guardian, anyone with threshold)
- Can a proposal be cancelled AFTER it passes but BEFORE execution?
- Can the cancellation mechanism be used to grief legitimate proposals?
- If a guardian/veto role exists: is it time-limited or permanent?

Tag: `[TRACE:propose → calldata={target,selector} → restricted={YES/NO} → self_referential={YES/NO}]`

---

## 3. Quorum and Threshold Analysis

### 3a. Quorum Computation
- Is quorum a fixed number or percentage of total supply?
- If percentage of supply: does supply change affect quorum? (token mint/burn changes the quorum threshold mid-vote)
- Can an attacker manipulate the quorum denominator? (inflate supply to lower effective quorum percentage)

### 3b. Threshold Edge Cases
- At exactly quorum (not quorum+1): does the proposal pass or fail? (`>=` vs `>`)
- At zero participation: what happens? (proposal fails, or defaults to pass?)
- Can abstain votes count toward quorum without counting for/against? (governance-specific - some implementations count abstain for quorum but not for approval)

### 3c. Voting Period Boundaries
- What happens if a vote is cast at the exact block where voting ends? (boundary precision)
- Can the voting period be changed while proposals are active? (retroactive period change)
- Is there a minimum voting period enforced? Can governance set period to 1 block?

Tag: `[BOUNDARY:quorum_threshold={exact} → votes_for={quorum} → passes={YES/NO}]`

---

## 4. Delegation and Vote Counting

### 4a. Delegation Chain Integrity
- Can delegation form cycles? (A delegates to B, B delegates to A)
- Is there a maximum delegation depth? (A → B → C → ... → unbounded gas)
- When delegation changes: are checkpoints updated correctly? (old delegate loses power, new delegate gains)
- Can self-delegation be used to double-count? (delegate to self + vote directly)

### 4b. Vote Weight Consistency
- Is vote weight at proposal snapshot equal to token balance at that block?
- Can token transfers AFTER snapshot but BEFORE vote change the outcome? (transfer tokens to a second account, vote with both)
- For staking/locking governance: are locked tokens counted correctly? (tokens locked in one contract, voting from another)

### 4c. Vote Tallying
- Are for/against/abstain tallied correctly in all code paths?
- Can a voter change their vote? If yes: is the old vote correctly subtracted?
- Can a voter vote multiple times? (nonce/bitmap check)

Tag: `[TRACE:delegate(from={A}, to={B}) → checkpoint_update={block} → power_transfer={correct/incorrect}]`

---

## Key Questions (must answer all)
1. Is voting power snapshot-based or live-balance? If snapshot: when is it taken relative to proposal creation?
2. Can proposal calldata target the governance or token contract itself?
3. Can quorum be manipulated by changing total supply during an active vote?
4. Is there a mandatory, non-bypassable delay between proposal approval and execution?
5. Can an attacker accumulate voting power via flash loan within the snapshot or voting window?

## Common False Positives
- **Block-delayed snapshot**: Snapshot taken at proposal creation with multi-block voting delay → flash loan in voting tx cannot affect historical snapshot
- **Timelock-enforced delay**: All execution goes through timelock with non-zero minimum delay → immediate exploitation prevented
- **Fixed quorum**: Quorum is absolute number (not percentage of supply) → supply changes don't affect threshold
- **Token transfer restrictions during voting**: Tokens locked when delegated/voting → cannot transfer and re-vote
- **Guardian with sunset**: Veto power has an expiration → temporary centralization that decays

## Step Execution Checklist (MANDATORY)

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1. Flash Loan Voting | YES | | Power source, snapshot window, delegation flash |
| 2. Proposal Lifecycle | YES | | Creation, content validation, execution, cancellation |
| 3. Quorum and Thresholds | YES | | Computation, edge cases, period boundaries |
| 4. Delegation and Vote Counting | IF delegation supported | | Chain integrity, weight consistency, tallying |
