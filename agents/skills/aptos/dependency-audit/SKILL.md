---
name: "dependency-audit"
description: "Trigger EXTERNAL_LIB flag detected (protocol uses third-party Move dependencies) - Used by Breadth agents, depth-external"
---

# Skill: DEPENDENCY_AUDIT

> **Trigger**: EXTERNAL_LIB flag detected (protocol uses third-party Move dependencies)
> **Used by**: Breadth agents, depth-external
> **Covers**: Third-party library security, upgrade policy risks, critical function correctness, transitive dependency chains

## Purpose

Audit third-party Move dependencies for security risks. Aptos protocols commonly depend on external math libraries, utility modules, and protocol SDKs. Unlike EVM (where dependencies are compiled into the contract), Move dependencies are on-chain modules that can be independently upgraded. A dependency upgrade can silently change the behavior of the audited protocol.

## Methodology

### STEP 1: Dependency Inventory

Parse `Move.toml` for all dependencies. Categorize each:

| # | Dependency | Source | Category | Upgrade Policy | Revision Pinned? |
|---|-----------|--------|----------|---------------|-----------------|
| 1 | AptosFramework | aptos-framework repo | FRAMEWORK | Framework governance | {rev hash or branch} |
| 2 | AptosStd | aptos-framework repo | FRAMEWORK | Framework governance | {rev hash or branch} |
| 3 | AptosToken | aptos-framework repo | FRAMEWORK | Framework governance | {rev hash or branch} |
| 4 | {third_party_lib} | {git URL} | THIRD_PARTY | {compatible/immutable/unknown} | {YES: rev=abc123 / NO: branch=main} |
| 5 | {sub_module} | local path | IN_SCOPE | N/A (part of audit) | N/A |

**Categories**:
- **FRAMEWORK**: `aptos_framework`, `aptos_std`, `aptos_token`, `aptos_token_objects` - trusted, framework-governance-controlled. Audit framework USAGE, not framework internals.
- **THIRD_PARTY**: External libraries (math utils, oracle SDKs, DEX interfaces). MUST audit all called functions.
- **IN_SCOPE**: Protocol's own sub-modules. Fully in scope.

**MANDATORY PARSE**: Read `Move.toml` (and any sub-package `Move.toml` files) for:
1. `[dependencies]` section entries
2. `git = "..."` URLs - identify the source repository
3. `rev = "..."` - pinned revision hash (safe) vs `branch = "main"` (dangerous)
4. `local = "..."` - in-scope sub-modules

### STEP 2: Upgrade Policy Risk Assessment

For each THIRD_PARTY dependency:

| Dependency | On-Chain Address | Upgrade Policy | Can Upgrade Without Protocol Knowledge? | Risk Level |
|-----------|-----------------|---------------|----------------------------------------|-----------|
| {lib} | {0x...} | immutable | NO | LOW |
| {lib} | {0x...} | compatible | YES - publisher can add functions, change logic | HIGH |
| {lib} | {0x...} | unknown | VERIFY ON-CHAIN | ASSESS |

**Check for each `compatible` dependency**:
1. Can the dependency publisher add new friend declarations (giving new modules access to internal state)?
2. Can the dependency publisher change function implementations (same signature, different logic)?
3. Can the dependency publisher add new public functions that interact with stored state?
4. Does the audited protocol store any state that the dependency module can access?
5. Is there a governance/multisig controlling the dependency's publisher address?

**Severity**: If a `compatible` third-party dependency can be upgraded to change behavior of functions the protocol calls, AND the protocol has no way to detect or prevent this -> minimum MEDIUM finding.

**Pinning check**: If `Move.toml` uses `branch = "main"` instead of `rev = "abc123"`:
- Build reproducibility is broken
- Developer may unknowingly compile against a different version
- Document as INFO finding (build hygiene)

### STEP 3: Critical Function Audit

For each function called from a THIRD_PARTY dependency:

#### 3a. Function Inventory

| # | Called Function | From Module | Parameters | Return Type | Frequency | Impact If Wrong |
|---|---------------|-------------|-----------|-------------|-----------|----------------|
| 1 | {lib::func()} | {our_module} | {params} | {return} | {every tx / periodic / init only} | {describe} |

#### 3b. Correctness Verification

For each critical function (called frequently OR high impact if wrong):

**Overflow/underflow check**:
1. Does the function handle multiplication overflow? (e.g., `a * b` where both are u64 - can overflow)
2. Does it handle division by zero?
3. Does it use intermediate u128 for precision in u64 arithmetic?
4. **Bit shift safety**: Does it use `<<` or `>>`? If so, is the shift amount bounded to < 64 (for u64) or < 128 (for u128)? Unbounded bit shifts are a known attack vector (historical exploit: bit shift overflow in a custom shift helper allowed minting tokens from minimal liquidity).

**Edge case check**:
| Input | Expected Output | Actual Output | Correct? |
|-------|----------------|---------------|----------|
| 0 | {expected} | {verify} | YES/NO |
| 1 | {expected} | {verify} | YES/NO |
| MAX_U64 | {expected: revert or handled} | {verify} | YES/NO |
| MAX_U128 | {expected} | {verify} | YES/NO |

**Specification check**:
- Does the function have documented behavior? (comments, spec blocks)
- Does the implementation match the specification?
- If the function is a math operation: verify against a reference implementation or mathematical formula

#### 3c. Trust Boundary Analysis

For each third-party function call:

| Call | Trusts Dependency To | What If Dependency Lies/Breaks | Detection? |
|-----|---------------------|-------------------------------|-----------|
| {lib::get_price()} | Return accurate price | Protocol uses wrong price → fund loss | {sanity check present?} |
| {lib::sqrt(x)} | Return correct sqrt | Wrong math → accounting error | {no detection} |

**Check**: Does the protocol validate the RETURN VALUE of third-party calls? Or does it blindly trust the result?

If no validation AND high impact -> FINDING.

### STEP 4: Transitive Dependency Analysis

Check whether third-party dependencies have their own dependencies:

#### 4a. Dependency Tree

```
Protocol
├── aptos_framework (FRAMEWORK)
├── third_party_lib_A
│   ├── aptos_framework (FRAMEWORK - OK, shared)
│   └── third_party_lib_B (THIRD_PARTY - audit this!)
│       └── aptos_std (FRAMEWORK - OK)
└── third_party_lib_C
    └── (no additional deps)
```

#### 4b. Transitive Risk Assessment

| Transitive Dependency | Reached Via | Upgrade Policy | Audited? | Risk |
|-----------------------|-----------|---------------|---------|------|
| {lib_B} | lib_A -> lib_B | {policy} | YES/NO | {assess} |

**Check**:
1. Are ALL transitive dependencies pinned to specific revisions?
2. Can a transitive dependency be upgraded independently, changing the behavior of the direct dependency?
3. Are there version conflicts (two dependencies requiring different versions of the same module)?

## Key Questions (Must Answer All)

1. **Pinning**: Are all third-party dependencies pinned to specific git revisions?
2. **Upgrade risk**: Can any dependency be upgraded without the protocol's knowledge?
3. **Math safety**: Do all third-party math functions handle overflow, zero, and boundary inputs correctly?
4. **Bit shift safety**: Are all bit shift operations bounded? (Critical after Cetus exploit)
5. **Trust validation**: Does the protocol validate return values from third-party calls?
6. **Transitive exposure**: Are there unaudited transitive dependencies?

## Common False Positives

1. **Framework dependencies**: `aptos_framework`, `aptos_std`, `aptos_token` are framework-governed and heavily audited - do not flag as third-party risk (but DO audit usage patterns)
2. **Immutable dependencies**: If the on-chain module is published with `immutable` policy, upgrade risk is zero
3. **Pinned to audited revision**: If the dependency is pinned to a specific, known-audited revision, transitive upgrade risk is build-time only (not runtime)
4. **Standard math operations**: Framework-provided `math64::mul_div()` and similar are well-tested - focus audit on third-party math libraries

## Output Schema

```markdown
## Finding [DEP-N]: Title

**Verdict**: CONFIRMED / PARTIAL / REFUTED / CONTESTED
**Step Execution**: ✓1,2,3,4 | ✗N(reason) | ?N(uncertain)
**Rules Applied**: [R1:✓/✗, R4:✓/✗, R8:✓/✗, R10:✓/✗]
**Severity**: Critical/High/Medium/Low/Info
**Location**: Move.toml or module_name.move:LineN

**Dependency**: {name and source}
**Risk Type**: UPGRADE_RISK / MATH_ERROR / TRUST_BOUNDARY / TRANSITIVE_EXPOSURE
**Upgrade Policy**: {immutable/compatible/unknown}

**Description**: What's wrong
**Impact**: What can happen (silent behavior change, math error, fund loss)
**Evidence**: Code showing the dependency usage and risk

### Precondition Analysis (if PARTIAL/REFUTED)
**Missing Precondition**: [What blocks exploitation]
**Precondition Type**: STATE / ACCESS / TIMING / EXTERNAL / BALANCE

### Postcondition Analysis (if CONFIRMED/PARTIAL)
**Postconditions Created**: [What conditions this creates]
**Postcondition Types**: [List applicable types]
**Who Benefits**: [Who can use these]
```

## Step Execution Checklist (MANDATORY)

| Step | Required | Completed? | Notes |
|------|----------|------------|-------|
| 1. Dependency Inventory | YES | ✓/✗/? | All Move.toml entries parsed and categorized |
| 2. Upgrade Policy Risk | FOR EACH third-party dep | ✓/✗/? | On-chain policy verified |
| 3a. Function Inventory | YES | ✓/✗/? | All called functions from third-party listed |
| 3b. Correctness Verification | FOR EACH critical function | ✓/✗/? | Overflow, zero, MAX tested |
| 3c. Trust Boundary Analysis | YES | ✓/✗/? | Return value validation checked |
| 4. Transitive Dependency Analysis | IF transitive deps exist | ✓/✗(N/A)/? | Full tree mapped |

If any step skipped, document valid reason (N/A, no third-party deps, all deps immutable).
