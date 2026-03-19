---
name: "nft-protocol-security"
description: "Protocol Type Trigger nft (detected when ERC721/ERC1155 with marketplace, minting, staking, or collateral logic found) - Inject Into Breadth agents, depth-token-flow, depth-edge..."
---

# Injectable Skill: NFT Protocol Security

> **Protocol Type Trigger**: `nft` (detected when ERC721/ERC1155 with marketplace, minting, staking, or collateral logic found)
> **Inject Into**: Breadth agents, depth-token-flow, depth-edge-case
> **Language**: EVM only (Solana/Move NFT models use different mechanisms without callbacks or enumeration)
> **Finding prefix**: `[NFT-N]`

## Orchestrator Decomposition Guide
When decomposing this skill into depth agent investigation questions, map sections to domains:
- Sections 1, 2: depth-token-flow (callback flows, approval/transfer paths)
- Section 3: depth-edge-case (enumeration invariants, boundary states)
- Section 4: depth-state-trace (ownership state consistency, metadata integrity)

## When This Skill Activates

Recon detects NFT protocol patterns: ERC721/ERC1155 with state-modifying logic beyond simple transfer (marketplace listing, staking, collateral, minting with conditions, royalty enforcement, batch operations).

Pure ERC721/ERC1155 token implementations without protocol logic do NOT trigger this skill.

---

## 1. Callback Reentrancy Surface

For each function that triggers NFT callbacks:

### 1a. Safe Transfer Callback Inventory
Enumerate all code paths that invoke `_safeMint`, `_safeTransfer`, `safeTransferFrom`, or `onERC1155Received`/`onERC1155BatchReceived`:

| # | Function | Callback Triggered | State Modified BEFORE Callback | State Modified AFTER Callback | Reentrancy Guard? |
|---|----------|-------------------|-------------------------------|------------------------------|-------------------|

For each entry:
- Is all critical state updated BEFORE the callback? (checks-effects-interactions)
- Can the callback recipient re-enter the calling contract?
- Can the callback recipient REVERT selectively to reject unwanted outcomes and retry until a desired outcome occurs?
- Pattern: `_safeMint(to, tokenId)` → `onERC721Received` callback → recipient reverts if assigned token has undesirable properties → retry until desired properties assigned.

### 1b. Batch Callback Completeness
For contracts implementing ERC1155:
- Is `onERC1155Received` implemented for single transfers?
- Is `onERC1155BatchReceived` implemented for batch transfers?
- If batch callback is MISSING: `safeBatchTransferFrom` will revert, blocking batch settlement/distribution.
- Do both callbacks return the correct selector?

Tag: `[TRACE:_safeMint → onERC721Received callback → state_before={list} → reentrant_path={YES/NO}]`

---

## 2. Approval and Transfer Path Analysis

### 2a. Approval Scope
For each approval mechanism:
- `approve(address, tokenId)`: per-token approval. Is approval cleared on transfer?
- `setApprovalForAll(address, bool)`: blanket approval. Can an approved operator transfer ANY token?
- Is there a mechanism to revoke approvals? Can approval persist across ownership changes?

### 2b. Transfer Authorization
For each transfer function:
- Who can transfer? (owner, approved, operator)
- Is authorization checked for ALL transfer code paths? (direct, marketplace, staking, collateral seizure)
- Pattern: protocol custody contract has `setApprovalForAll` from users → contract can transfer any user's NFTs → compromise of contract = compromise of all approved NFTs.

### 2c. Royalty Bypass
If royalties are enforced:
- Can transfers occur through paths that bypass royalty checks? (direct `transferFrom` vs marketplace `executeSale`)
- Are royalties enforced at the token level (ERC2981) or marketplace level?
- If marketplace-level only: direct transfer bypasses royalties.

Tag: `[TRACE:transfer_path={function} → auth_check={method} → royalty_enforced={YES/NO}]`

---

## 3. Enumeration and Index Integrity

For contracts using ERC721Enumerable or custom enumeration:

### 3a. Index Structure Consistency
- What data structures track token ownership enumeration? (`_ownedTokens`, `_allTokens`, index mappings)
- For every state-changing operation (mint, burn, transfer): are ALL index structures updated atomically?
- Pattern: override `_beforeTokenTransfer` (OZ v4) or `_update` (OZ v5) without calling `super` → index structures become stale.

### 3b. Burn and Transfer Edge Cases
- After burn: does `tokenOfOwnerByIndex` still return correct values? Is `totalSupply` decremented?
- After transfer: does old owner's index shrink and new owner's index grow?
- At boundary: single-token owner burns their only token → empty enumeration handles correctly?

### 3c. Batch Operation Atomicity
For batch mint/burn/transfer:
- Are indices updated for EACH token in the batch, or only once at the end?
- Can a partial failure in a batch leave indices in an inconsistent state?
- Gas cost at maximum batch size: does it exceed block gas limit?

Tag: `[BOUNDARY:burn_last_token → _ownedTokens[owner].length={0} → tokenOfOwnerByIndex={result}]`

---

## 4. Metadata and State Consistency

### 4a. Token URI Integrity
If `tokenURI` or `uri` returns dynamic content:
- For ERC1155: does `uri(uint256 id)` return a template with literal `{id}` placeholder per spec? Or a fully resolved URL? (clients expect to substitute the zero-padded hex ID client-side)
- Can metadata be changed after mint? By whom? Does change emit event?
- Is metadata stored on-chain or off-chain? If off-chain: what happens if the URI host is unreachable?

### 4b. Token Property Assignment
If tokens have properties assigned at mint time (rarity, type, attributes):
- Is the assignment deterministic or random?
- If random: is the randomness source manipulable? (block.timestamp, block.prevrandao, weak PRNG)
- Can the minter influence which properties are assigned? (selective minting via callback revert)
- Cross-reference FLASH_LOAN_INTERACTION if properties affect economic value.

### 4c. Ownership State During Custody
When tokens are deposited into protocol custody (staking, collateral, escrow):
- Does `ownerOf(tokenId)` return the protocol address or the depositor?
- Are user rights (claim, withdraw, liquidate) tracked correctly in protocol state?
- If the protocol is compromised: can deposited NFTs be recovered?

Tag: `[TRACE:mint → property_assignment={method} → randomness_source={source} → manipulable={YES/NO}]`

---

## Key Questions (must answer all)
1. For each `_safeMint`/`_safeTransfer`: is critical state updated BEFORE the callback?
2. For ERC1155: are BOTH single and batch callbacks implemented with correct selectors?
3. For enumerable tokens: do burn/transfer operations update ALL index structures?
4. For metadata: does `uri()` follow the spec for the token standard used?
5. For custody protocols: is depositor ownership tracked independently from `ownerOf`?

## Common False Positives
- **Non-reentrant safe transfers**: `_safeMint` within `nonReentrant` modifier → callback reentrancy blocked
- **Standard OZ implementation**: Inherits `ERC721Enumerable` or `ERC1155` without overriding internal hooks → indices maintained by parent
- **Immutable metadata**: Token URI set at mint and never changeable → no metadata manipulation
- **Trusted recipients only**: Safe transfers only to protocol-controlled addresses (not user-supplied) → callback revert/reentrancy not user-exploitable

## Step Execution Checklist (MANDATORY)

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1. Callback Reentrancy Surface | IF safe mint/transfer used | | Callback inventory, batch completeness |
| 2. Approval and Transfer Paths | YES | | Authorization, scope, royalty bypass |
| 3. Enumeration and Index Integrity | IF enumerable | | Index consistency across operations |
| 4. Metadata and State Consistency | YES | | URI spec, property assignment, custody |
