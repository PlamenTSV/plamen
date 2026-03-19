---
name: "external-precondition-audit"
description: "Trigger Pattern Any external module interaction detected in attack_surface.md - Inject Into Breadth agents (merged via M5 hierarchy)"
---

# EXTERNAL_PRECONDITION_AUDIT Skill

> **Trigger Pattern**: Any external module interaction detected in attack_surface.md
> **Inject Into**: Breadth agents (merged via M5 hierarchy)
> **Constraint**: Interface-level inference only -- no production fetch required

For every external module the protocol interacts with:

## 1. Interface-Level Requirement Inference

From the `use` imports and function calls to external modules, infer what the external module requires:

| External Function Called | Module::Function | Parameters Passed | Likely Preconditions (from signature + abort codes) | Our Protocol Validates? |
|--------------------------|-----------------|-------------------|-----------------------------------------------------|------------------------|

**Inference method**: Read the function signature, type parameters, ability constraints, and abort conditions. Example: `coin::withdraw<CoinType>(account: &signer, amount: u64)` -> infer that `account` must have sufficient balance, `CoinType` must be initialized, amount must be > 0. Check abort codes in framework source if available.

**Aptos-specific patterns**:
- `&signer` parameters: does external module require the signer to own a specific resource?
- Generic type parameters `<T>`: does external module require `T` to be registered/initialized?
- `Object<T>` parameters: does external module validate object ownership or type?
- Abort conditions: enumerate all `assert!` / `abort` in external function that could revert our call

## 2. Return Value Consumption

| External Call | Return Type | How Protocol Uses Return | Failure Mode if Return Unexpected |
|--------------|-------------|-------------------------|----------------------------------|

For each return value:
- What happens if it returns 0? What happens if it returns `MAX_U64`?
- What happens if the external call aborts?
- For `Option<T>` returns: does our protocol handle `none` correctly?
- For `FungibleAsset` returns: is metadata validated after receiving?
- For `Object<T>` returns: is the object type verified before use?

## 3. State Dependency Mapping

| Protocol State | Depends on External State | External Module Upgradeable? | State Can Change Without Our Knowledge? |
|---------------|--------------------------|-----------------------------|-----------------------------------------|

For each dependency:
- **Upgrade risk**: Aptos modules are upgradeable by default (`compatible` policy). Can the external module add new abort conditions to a function we call? Can it change return value semantics within compatible upgrade bounds?
- **Immutability check**: Is the external module published as `immutable`? If so, behavior is frozen.
- **State mutation timing**: Can external module state change between our module's read and use within the same transaction? (e.g., another instruction in a multi-instruction transaction modifies external state)
- **Framework dependency**: If depending on `aptos_framework` modules, are there governance-controlled parameters that could change? (e.g., `transaction_fee`, `staking_config`)

## Instantiation Parameters

```
{CONTRACTS}           -- List of modules to analyze
{EXTERNAL_MODULES}    -- External modules identified during recon
{FRAMEWORK_DEPS}      -- aptos_framework / aptos_std / aptos_token dependencies
```

## Output Schema

For each finding:

```markdown
## Finding [EP-N]: Title

**Verdict**: CONFIRMED / PARTIAL / REFUTED / CONTESTED
**Step Execution**: S1,S2,S3 | X(reasons) | ?(uncertain)
**Rules Applied**: [R1:Y, R4:Y, R8:Y]
**Severity**: Critical/High/Medium/Low/Info
**Location**: module::function (source_file.move:LineN)

**External Dependency**: {module::function}
**Failure Mode**: {what breaks}

**Description**: What's wrong
**Impact**: What can happen (abort DoS, wrong state, fund loss)
**Evidence**: Code showing dependency and missing validation
```

## Step Execution Checklist

| Section | Required | Completed? |
|---------|----------|------------|
| 1. Interface-Level Requirement Inference | YES | Y/N/? |
| 2. Return Value Consumption | YES | Y/N/? |
| 3. State Dependency Mapping | YES | Y/N/? |
