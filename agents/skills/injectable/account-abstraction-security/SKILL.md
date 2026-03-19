---
name: "account-abstraction-security"
description: "Protocol Type Trigger account_abstraction (detected when ERC-4337 interfaces, EntryPoint, UserOperation, or Paymaster patterns found) - Inject Into Breadth agents, depth-external"
---

# Injectable Skill: Account Abstraction Security

> **Protocol Type Trigger**: `account_abstraction` (detected when ERC-4337 interfaces, EntryPoint, UserOperation, or Paymaster patterns found)
> **Inject Into**: Breadth agents, depth-external
> **Language**: EVM only (other VMs handle account abstraction natively without smart contract validation stacks)
> **Finding prefix**: `[AA-N]`

## Orchestrator Decomposition Guide
When decomposing this skill into depth agent investigation questions, map sections to domains:
- Section 1: depth-external (validation flow, external calls to EntryPoint)
- Section 2: depth-edge-case (paymaster edge cases, gas bounds)
- Section 3: depth-state-trace (signature validation state, module registry)
- Section 4: depth-token-flow (fee payment flows, token approvals)

## When This Skill Activates

Recon detects ERC-4337 patterns: `UserOperation`, `IAccount`, `IPaymaster`, `EntryPoint`, `validateUserOp`, `validatePaymasterUserOp`, `postOp`, `isValidSignature` (ERC-1271), or smart account/wallet factory patterns.

---

## 1. UserOperation Validation Flow

For each `validateUserOp` implementation:

### 1a. Signature Verification
- What signature scheme is used? (ECDSA, multi-sig, passkey/WebAuthn, session keys)
- Is the signature verified against the CORRECT signer(s)?
- Is the `userOpHash` computed correctly (includes `chainId`, `entryPoint`, `nonce`)?
- Can a valid signature for one operation be replayed for a different operation? (nonce management)

### 1b. Nonce Management
- Is the nonce scheme sequential, 2D (key + sequence), or custom?
- Can nonce be skipped or reused?
- For 2D nonces: can different keys interfere with each other?
- Does the nonce validation happen BEFORE or AFTER signature verification?

### 1c. Return Value Correctness
- `validateUserOp` must return `validationData` encoding `(authorizer, validUntil, validAfter)`.
- Does the return value correctly encode time bounds?
- Does returning `0` (success) vs `1` (failure) vs packed data follow the spec?
- Can the function return success for an INVALID operation?

Tag: `[TRACE:validateUserOp → sig_scheme={scheme} → hash_includes_chainId={YES/NO} → nonce_check={method}]`

---

## 2. Paymaster Validation

For each `validatePaymasterUserOp` implementation:

### 2a. Pre-Validation vs Post-Execution
- What validation occurs in `validatePaymasterUserOp` (pre-execution)?
- What validation occurs in `postOp` (post-execution)?
- If payment validation is DEFERRED to `postOp`: what happens if `postOp` reverts? Does the paymaster eat the cost?
- Can a user consume gas without ever paying? (trigger `validatePaymasterUserOp` success → execute expensive operation → `postOp` fails to collect payment)

### 2b. Payment Token Handling
If paymaster accepts ERC-20 for gas payment:
- Is the token approval checked in `validatePaymasterUserOp` or `postOp`?
- Can the user revoke approval BETWEEN validation and `postOp`? (inner execution context)
- Is the exchange rate (token/gas) manipulable? (oracle dependency → cross-reference ORACLE_ANALYSIS)
- Is there a maximum gas sponsor amount to prevent griefing?

### 2c. Paymaster Context Integrity
- Data passed via `context` from `validatePaymasterUserOp` to `postOp`: can it be tampered with?
- Is the context length bounded? (unbounded context → gas griefing)
- Does `postOp` handle all three modes? (`opSucceeded`, `opReverted`, `postOpReverted`)

Tag: `[TRACE:paymaster_validate → deferred_checks={list} → postOp_can_fail={YES/NO} → payment_collected={guaranteed/conditional}]`

---

## 3. Signature Validation Modules (ERC-1271)

For each `isValidSignature` implementation:

### 3a. Delegation Security
- Is signature validation delegated to external modules/plugins?
- If yes: is the module registry access-controlled? (who can add/remove modules)
- Can a malicious module return `0x1626ba7e` (valid) for ANY hash? (always-true validator)
- Is there a timelock/guardian approval for module changes?

### 3b. Module Interaction Safety
- Can modules call back into the account contract? (reentrancy via validation)
- Can modules access account funds during validation?
- Is there a gas limit on module `isValidSignature` calls?

### 3c. Session Key Constraints
If session keys or scoped permissions are supported:
- Are permissions correctly scoped? (target contract, function selector, value limit, time window)
- Can a session key exceed its permission scope through calldata manipulation?
- Are session key permissions checked BEFORE or AFTER signature verification?

Tag: `[TRACE:isValidSignature → delegated_to={module} → registry_access={control} → always_valid={YES/NO}]`

---

## 4. Factory and Initialization

### 4a. Counterfactual Address Binding
- Is the wallet's initialization data (owner, modules, config) committed to the CREATE2 salt/address?
- Can an attacker deploy a wallet at the expected address with DIFFERENT initialization parameters?
- Pattern: `CREATE2(salt=hash(owner))` is safe. `CREATE2(salt=nonce)` without binding owner → attacker deploys with their own owner at the victim's expected address.

### 4b. Pre-Deployment Fund Safety
- Can funds be sent to a counterfactual address before deployment?
- If yes: can anyone deploy the wallet at that address and drain the funds?
- Is there a race condition between fund deposit and wallet deployment?

### 4c. Re-Initialization Protection
- After deployment: can `initialize()` be called again?
- Is the initializer modifier (`initializer`/`reinitializer`) correctly applied?
- For proxy-based accounts: can the implementation be initialized separately from the proxy?

Tag: `[TRACE:factory_deploy → salt_binds_owner={YES/NO} → pre_deploy_funds={safe/vulnerable}]`

---

## Key Questions (must answer all)
1. Does `validateUserOp` correctly verify signatures against the operation hash including chain ID?
2. Can the paymaster be drained by operations that validate but fail to pay in `postOp`?
3. Are signature validation modules restricted to a trusted registry with access control?
4. Is the wallet's CREATE2 address bound to its initialization parameters (owner, config)?
5. Can session keys or scoped permissions be exceeded through calldata manipulation?

## Common False Positives
- **EntryPoint-enforced nonce**: If using standard EntryPoint nonce management → protocol-level nonce check may be redundant
- **Trusted module whitelist with timelock**: Module registry behind multisig + timelock → low risk of malicious module
- **Paymaster with prepaid deposits**: If paymaster requires pre-deposited balance (not deferred payment) → `postOp` failure doesn't lose funds
- **Standard factory with owner-bound salt**: `CREATE2` salt includes `keccak256(owner)` → counterfactual address is owner-specific

## Step Execution Checklist (MANDATORY)

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1. UserOperation Validation | IF `validateUserOp` present | | Signature, nonce, return value |
| 2. Paymaster Validation | IF paymaster present | | Pre/post validation, payment token |
| 3. Signature Validation Modules | IF ERC-1271 / modules | | Delegation, session keys |
| 4. Factory and Initialization | IF wallet factory present | | Address binding, re-init |
