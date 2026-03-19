---
name: "signature-verification-audit"
description: "Trigger HAS_SIGNATURES flag in template_recommendations.md (recon detects signature verification patterns - see chain-specific grep patterns in TASK 6) - Agent Type general-purp..."
---

# Niche Agent: Signature Verification Audit

> **Trigger**: `HAS_SIGNATURES` flag in `template_recommendations.md` (recon detects signature verification patterns - see chain-specific grep patterns in TASK 6)
> **Agent Type**: `general-purpose` (standalone niche agent, NOT injected into another agent)
> **Budget**: 1 depth budget slot in Phase 4b iteration 1
> **Finding prefix**: `[SIG-N]`
> **Added in**: v1.0.0

## When This Agent Spawns

Recon Agent 3 (Patterns + Surface + Templates) greps for signature-related patterns during TASK 6. If any are found, recon sets `HAS_SIGNATURES` flag in the BINDING MANIFEST under `## Niche Agents`.

Chain-specific trigger patterns:
- **EVM**: `ecrecover`, `ECDSA.recover`, `SignatureChecker`, `isValidSignature`, `EIP712`, `domainSeparator`, `permit(`
- **Solana**: `ed25519_program`, `Secp256k1`, `verify_signature`, `Signature`, `ed25519_instruction`, `Secp256k1Program`
- **Aptos**: `ed25519::verify`, `multi_ed25519`, `account::rotate_authentication_key`, `SignedMessage`, `signature::verify`
- **Sui**: `ecdsa_k1::secp256k1_verify`, `ed25519::ed25519_verify`, `hash::blake2b256`, `ecdsa_r1`

## Why a Dedicated Agent

Signature bugs span 9 distinct sub-classes that interact with each other (e.g., missing replay protection + missing chain binding = cross-chain replay). A scanner sub-check catches surface patterns but misses logic-level issues (is the nonce actually incremented? is the signature bound to this chain and contract?). Breadth agents lack the focus to trace a signature from construction through verification to consumption.

## Agent Prompt Template

```
Task(subagent_type="general-purpose", prompt="
You are the Signature Verification Agent. You audit all signature creation, verification, and consumption patterns.

## Your Inputs
Read:
- {SCRATCHPAD}/detected_patterns.md (signature-related patterns flagged by recon)
- {SCRATCHPAD}/function_list.md (all functions)
- {SCRATCHPAD}/state_variables.md (nonce/replay-protection-related state)
- Source files containing signature operations

## CHECK 1: Signature Validation Completeness

For EACH signature verification call site:

| Call Site | Invalid Signature Handled? | Signer Recovery Validated? | Nonce Verified? | Deadline Checked? | Scope Bound? | Gap? |
|-----------|--------------------------|---------------------------|-----------------|-------------------|-------------|------|

Chain-specific verification functions:
- **EVM**: `ecrecover` returns `address(0)` on invalid signature - must check return != address(0). `ECDSA.recover` reverts on invalid (safer).
- **Solana**: `ed25519_program` instruction introspection - verify the instruction exists in the transaction AND the signed data matches expectations. Missing verification = anyone can claim any signature.
- **Aptos**: `ed25519::signature_verify_strict` returns bool - must check return value. `multi_ed25519::verify` for multisig schemes.
- **Sui**: `ecdsa_k1::secp256k1_verify` / `ed25519::ed25519_verify` return bool - must check return value.

## CHECK 2: Replay Protection (Nonce Management)

For EACH nonce-based or flag-based replay protection:

| Replay Guard | Type (nonce/mapping/bitmap/flag) | Incremented/Set Before Use? | Can Be Reused? | Shared Across Functions? | Gap? |
|-------------|--------------------------------|---------------------------|----------------|------------------------|------|

- Sequential nonces: verify increment happens BEFORE or DURING validation, not after external calls
- Mapping-based (used[hash]): verify the key is unique per message, not just per signer
- Check: can a signature be used across different functions that share the same replay protection space?
- **Solana-specific**: if using instruction introspection for ed25519 verification, check that the SAME transaction cannot include the ed25519 instruction twice with different signed data
- **Aptos/Sui**: if replay protection uses a `Table` or `VecMap`, check for key collision across different message types

## CHECK 3: Signature Scope Binding

Verify each signature is bound to the intended chain, contract/program/module, and operation:

| Signature | Chain-Bound? | Contract-Bound? | Function-Bound? | Gap? |
|-----------|-------------|-----------------|----------------|----|

Chain-specific binding mechanisms:
- **EVM (EIP-712)**: Domain separator must include `chainId` (recomputed on fork) and `verifyingContract` (must be `address(this)`). If cached at deployment and not recomputed on `block.chainid` change → cross-chain replay. If hardcoded address → breaks on proxy upgrade.
- **Solana**: Signed message must include the program ID. If not, signature from one program can be replayed on another. Check: does the ed25519 instruction data include the target program's public key?
- **Aptos**: Signed message should include the module address (`@module_addr`). Resource account addresses are deterministic - verify the signed data cannot be replayed on a different resource account with the same seed.
- **Sui**: Signed message should include the package ID. After package upgrade, verify signatures from old versions cannot be used on new package.

General checks (all chains):
- If signed message omits the function/operation identifier → signature valid for different operations within the same contract
- If signed message omits a unique identifier (nonce, timestamp, tx hash) → signature is replayable
- Check meta-transaction/gasless relayers: does the relayed call include the target address in the signed data?

## CHECK 4: Off-Chain Approval Patterns

If the protocol accepts off-chain authorizations (permits, gasless approvals, signed orders, meta-transactions):

| Approval Type | Front-Run Resistant? | Fallback on Failure? | Deadline Enforced? | Revocable? | Gap? |
|-------------|---------------------|---------------------|-------------------|-----------|----|

- **EVM (EIP-2612 permit)**: `permit() + transferFrom()` in same tx can be front-run - attacker calls `permit()` first, user's tx reverts. Safe pattern: wrap permit in try/catch, fall back to existing allowance.
- **Solana (signed orders)**: If protocol accepts pre-signed transaction instructions, check: can an attacker submit the signed instruction before the intended user? Can the order be partially filled and replayed?
- **Aptos/Sui (signed messages)**: If protocol accepts off-chain signed messages for state changes, check: can the message be submitted by anyone, or only the signer? Is there a deadline after which the message expires?
- **All chains**: Does the protocol REQUIRE the off-chain authorization to succeed, or does it gracefully handle front-running/race conditions?

## CHECK 5: Signature Malleability

For EACH signature verification:

| Verification | Malleable? | Signatures Used as Keys/IDs? | Framework-Wrapped? | Gap? |
|-------------|-----------|------------------------------|-------------------|------|

- **ECDSA (EVM)**: For any valid (r, s, v), (r, n-s, v^1) is also valid. If signatures are used as unique identifiers (mapping keys, dedup), malleability allows replay. OpenZeppelin's `ECDSA.recover` enforces `s <= n/2`. Check if protocol uses raw `ecrecover` without this bound.
- **Ed25519 (Solana/Aptos/Sui)**: Ed25519 signatures are NOT malleable when using strict verification (`ed25519_dalek` with `verify_strict`). However, non-strict verification may accept multiple valid signatures for the same message. Check which verification function is used.
- **All chains**: If the protocol stores or compares signatures as bytes (mapping keys, dedup sets), ANY malleability allows bypass. If signatures are only used for signer recovery (not as identifiers), malleability is not exploitable.

## CHECK 6: Cross-Chain and Cross-Protocol Replay

| Signature | Chain-Bound? | Protocol-Bound? | Version-Bound? | Gap? |
|-----------|-------------|-----------------|---------------|----|

- If the signed data does not include a chain identifier → signature valid on any chain with the same protocol deployed
- If the signed data does not include the protocol/program/module address → signature valid on any protocol using the same message format
- **EVM-specific**: Check domain separator for `chainId` and `verifyingContract`
- **Solana-specific**: Check if program ID is in the signed data
- **Aptos-specific**: Check if module address is in the signed data; also check if resource account seed makes the address predictable across chains
- **Sui-specific**: Check if package ID is in the signed data; after upgrade, check if old signatures work on new package version
- **Multi-chain protocols**: If the same protocol is deployed on multiple chains, are signatures from Chain A replayable on Chain B?

## CHECK 7: Deadline and Expiry

| Signature Type | Has Deadline? | Deadline Enforced On-Chain? | Can Be 0 or MAX? | Gap? |
|---------------|--------------|----------------------------|-----------------|------|

- Signatures without deadlines are valid forever (even after key rotation, role revocation, permission changes)
- Check: can deadline be set to maximum value (e.g., `type(uint256).max`, `u64::MAX`) effectively making it permanent?
- Check: is the time source used correctly?
  - **EVM**: `block.timestamp` - off-by-one (>= vs >) can extend validity by 1 block
  - **Solana**: `Clock::unix_timestamp` - check for slot-vs-timestamp confusion
  - **Aptos**: `timestamp::now_seconds()` vs `now_microseconds()` - unit mismatch
  - **Sui**: `clock::timestamp_ms()` - milliseconds, not seconds

## CHECK 8: Signature Consumption Ordering

| Operation | Signature Checked Before State Change? | External Callbacks Safe? | Gap? |
|-----------|---------------------------------------|-------------------------|------|

- Verify: signature validation occurs BEFORE any state changes (checks-effects-interactions pattern)
- If signature verification involves external calls, check for reentrancy:
  - **EVM**: `isValidSignature` (ERC-1271) calls an external contract - reentrancy vector if state is modified before the call
  - **Solana**: CPI to ed25519 program is safe (system program), but CPI to a custom verification program could be malicious
  - **Aptos/Sui**: External module calls for verification - check if the called module can re-enter the calling module via friend functions or public entry points

## Output Requirements
Write to {SCRATCHPAD}/niche_signature_findings.md
Use finding IDs: [SIG-1], [SIG-2]...
Use standard finding format with Verdict, Severity, Location, Description, Impact, Evidence.
Maximum 8 findings - prioritize by severity.

## Quality Gate
Every finding MUST cite the specific signature verification code (file:line) AND the missing/broken protection.
Do NOT flag patterns that framework-provided safe wrappers already handle (e.g., OpenZeppelin ECDSA.recover, Anchor's ed25519 instruction parsing) - verify whether the protocol uses the raw primitive or a safe wrapper.

Return: 'DONE: {N} signature findings - {R} replay, {M} malleability, {S} scope binding, {A} approval, {E} validation, {O} other'
")
```

## Integration Point

This agent's output (`niche_signature_findings.md`) is read by:
- Phase 4a inventory merge (after Phase 4b iteration 1)
- Phase 4c chain analysis (signature bugs can enable other attacks - e.g., signature replay enables unauthorized withdrawal)
- Phase 6 report writers
