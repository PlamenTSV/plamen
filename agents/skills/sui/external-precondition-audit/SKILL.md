---
name: "external-precondition-audit"
description: "Trigger Pattern Any external package function call detected in program - Inject Into Breadth agents (merged via M5 hierarchy)"
---

# Skill: External Precondition Audit (Sui)

> **Trigger Pattern**: Any external package function call detected in program
> **Inject Into**: Breadth agents (merged via M5 hierarchy)
> **Finding prefix**: `[EPA-N]`
> **Rules referenced**: R1, R4, R8, R10
> **Constraint**: Interface-level inference only -- no production fetch required

```
use.*external|friend|public.*package|transfer::public_|dynamic_field|coin::from_balance|
clock::timestamp_ms|sui::pay|dex|swap|oracle|price_feed
```

For every external package the protocol calls:

## 1. Interface-Level Requirement Inference

From the imported module signatures, infer what the external package requires:

| External Function Called | Parameters Passed | Likely Preconditions (from signature) | Our Protocol Validates? | Package Immutable? |
|-------------------------|-------------------|--------------------------------------|------------------------|--------------------|

**Inference method**: Read the function signature, type constraints, and any doc comments. Example: `pool::swap<A, B>(pool: &mut Pool<A, B>, coin_in: Coin<A>, ...)` -> infer that `pool` must be the correct pool for `A/B` pair, `coin_in` must have sufficient balance, and return `Coin<B>` may have zero value (slippage).

**Package immutability check** (CRITICAL Sui-specific):
- Is the external package immutable (`UpgradeCap` destroyed)?
- If upgradeable: who holds the `UpgradeCap`? What upgrade policy (compatible, additive, dependency-only)?
- If upgradeable with `compatible` policy: the external package can change function behavior arbitrarily. Apply Rule 4 (adversarial assumption) -- treat the external package as potentially malicious after upgrade.
- If immutable: behavior is fixed, trust boundary is clear.

## 2. Return Value Consumption

| External Call | Return Type | How Protocol Uses Return | Failure Mode if Return Unexpected |
|--------------|-------------|-------------------------|----------------------------------|

For each return value:
- What happens if it returns a `Coin<T>` with zero balance? (division by zero, incorrect share calculation)
- What happens if it returns a `Coin<T>` with less value than expected? (slippage not checked)
- What happens if the call aborts? (entire PTB aborts -- can this be used for griefing?)
- **Hot potato returns**: If the external call returns a hot potato (zero-ability struct), is the consuming function always reachable in the same PTB? If not, the PTB always aborts.

**Sui-specific**: External package calls within a PTB share the same abort scope. If any external call aborts, the entire PTB reverts. Model: can an attacker cause an external call to abort to grief a user's multi-step PTB?

## 3. State Dependency Mapping

| Protocol State | Depends on External Shared Object | External State Can Change Between Epochs/Txns? |
|---------------|----------------------------------|------------------------------------------------|

For each dependency: model what happens when the external shared object state changes between our protocol's transactions.

**Sui-specific concerns**:
- Shared objects are ordered by consensus. Two transactions touching the same shared object are serialized. But transactions touching DIFFERENT shared objects can execute concurrently.
- If our protocol reads shared object A (external) and then writes shared object B (ours), another transaction can modify A between our read and our next access.
- **Cross-epoch state**: External shared objects may have epoch-dependent behavior (e.g., staking pools that update per epoch). Is our protocol aware of epoch boundaries?
- **Package upgrade state change**: If the external package upgrades, shared objects created by the old version may behave differently when accessed by functions from the new version. Does our protocol pin to a specific package version?

### 3b. Package Upgrade Risk Assessment

For each external package dependency:

| External Package | UpgradeCap Status | Upgrade Policy | Impact if Upgraded | Our Protocol's Mitigation |
|------------------|-------------------|---------------|-------------------|--------------------------|
| {package} | {destroyed (immutable) / held by {who}} | {compatible / additive / dep_only / immutable} | {behavior change risk} | {version pin / none} |

**Check**:
- Does the external package use `sui::package::UpgradeCap`? If so:
  - Who holds the `UpgradeCap`? (single admin, multisig, destroyed for immutability)
  - What upgrade policy is set? (`compatible` = can change anything, `additive` = can add but not change, `dep_only` = only dependency updates, `immutable` = frozen forever)
  - Can an upgrade change the behavior of functions our protocol depends on?
- Does our protocol pin to a specific package version, or does it follow upgrades automatically?
- If the external package upgrades with `compatible` policy: shared objects created by the old version may behave differently when accessed by the new version's functions. Our protocol may call into changed behavior without any code change on our side.

## Finding Template

```markdown
**ID**: [EPA-N]
**Verdict**: CONFIRMED / PARTIAL / REFUTED / CONTESTED
**Step Execution**: (see checklist below)
**Rules Applied**: [R1:___, R4:___, R8:___, R10:___]
**Severity**: Critical/High/Medium/Low/Info
**Location**: sources/{module}.move:LineN
**Title**: {missing external validation / unexpected return / state dependency}
**Description**: {specific issue with code reference}
**Impact**: {what attacker can achieve via the external package weakness}
```

---

## Step Execution Checklist (MANDATORY)

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1. Interface-Level Requirement Inference | YES | | Includes package immutability check |
| 2. Return Value Consumption | YES | | Hot potato return paths checked |
| 3. State Dependency Mapping | YES | | Cross-epoch + package upgrade state |
| 3b. Package Upgrade Risk | YES | | UpgradeCap holder + upgrade policy |

If any step skipped, document valid reason (N/A, no external packages, framework-only deps).
