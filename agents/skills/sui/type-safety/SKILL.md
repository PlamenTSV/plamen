---
name: "type-safety"
description: "Trigger Pattern Always (Sui Move) -- generic type exploitation - Inject Into Breadth agents, depth-state-trace"
---

# TYPE_SAFETY Skill

> **Trigger Pattern**: Always (Sui Move) -- generic type exploitation
> **Inject Into**: Breadth agents, depth-state-trace

For every generic function and parameterized type in the protocol:

**STEP PRIORITY**: Steps 4 (OTW Analysis) and 6 (Coin/Balance Type Safety) are where HIGH/CRITICAL severity findings most commonly hide. Do NOT rush these steps. If constrained, skip conditional sections before skipping 4 or 6.

## 1. Generic Function Inventory

Enumerate ALL functions with type parameters across all modules:

| Module | Function | Type Params | Constraints | Public? | Phantom? | Notes |
|--------|----------|-------------|-------------|---------|----------|-------|
| {mod} | {func} | `<T>`, `<T: store>`, etc. | {ability constraints} | YES/NO | YES/NO | {context} |

**Sui type parameter semantics**:
- `<T>` -- unconstrained. T can be ANY type. Maximally permissive.
- `<T: key + store>` -- T must be an object that can be freely transferred.
- `<T: drop>` -- T can be discarded. Often used for witness patterns.
- `<phantom T>` -- T is not used at runtime, only for type distinction (e.g., `Coin<phantom T>`). No ability constraints enforced on phantom params at the struct level.

## 2. Type Parameter Constraint Analysis

For each generic function, verify constraints are sufficient:

### 2a. Under-Constrained Parameters

| Function | Param | Constraint | Actually Used As | Sufficient? |
|----------|-------|-----------|-----------------|-------------|
| {func} | `T` | none | stored in dynamic field (needs `store`) | **NO** |
| {func} | `T` | `store` | used as `Coin<T>` balance | **NO** -- needs further check |

**Check**: For each type parameter, trace how it is actually used in the function body:
- If stored in a struct field -> needs at minimum `store`
- If used as an object -> needs `key`
- If discarded without explicit destruction -> needs `drop`
- If the function works correctly with ANY type -> unconstrained is correct

### 2b. Over-Constrained Parameters (Info-Level)

| Function | Param | Constraint | Actually Needed | Over-Constrained? |
|----------|-------|-----------|----------------|-------------------|
| {func} | `T` | `key + store + drop` | only `store` | YES -- limits usability |

**Note**: Over-constraining is not a security issue but limits composability. Document as Informational.

### 2c. Phantom Type Correctness

| Struct | Phantom Param | Used in Runtime Logic? | Type-Level Distinction Sound? |
|--------|--------------|----------------------|------------------------------|
| {struct} | `phantom T` | YES (BUG) / NO | YES/NO |

**Rule**: Phantom type parameters MUST NOT be used in runtime field types (non-phantom positions). If a phantom param is used in a non-phantom position, the compiler rejects it. But check: is the phantom param providing meaningful type distinction, or can an attacker substitute any type?

## 3. Type Witness Pattern Audit

Identify all witness patterns (structs used for one-time authorization):

| Witness Type | Module | Created In | Consumed In | Abilities | Singleton? |
|-------------|--------|------------|-------------|-----------|-----------|
| {name} | {mod} | {function} | {function} | `drop` only / none | YES/NO |

**Witness security checks**:
- [ ] Is the witness created ONLY in the intended function? (Check all `new` / constructor paths.)
- [ ] Is the witness consumed (dropped or destructured) immediately after use?
- [ ] Can the witness be stored? (If it has `store` -> it can persist beyond its intended scope -> FINDING.)
- [ ] Can the witness be copied? (If it has `copy` -> it can be reused -> FINDING.)
- [ ] Is the witness type public? (If the struct is public, external modules can potentially construct it if they can satisfy its fields.)

### 3a. Witness Forgery Check

For each witness type:
```
Can an attacker construct this witness type?
1. Is the struct definition public (`public struct`)? -> External modules CAN create instances if fields are accessible
2. Does the struct have fields? -> If no fields (unit struct), only the defining module can create it
3. Are all field types accessible to external modules? -> If yes, external construction possible
4. Is construction gated by `init` or capability? -> Check the gate
```

**Rule**: A witness with a public struct definition and publicly-accessible field types is forgeable from external modules. This is a CRITICAL finding if the witness gates value creation (coin minting, capability issuance, etc.).

## 4. One-Time Witness (OTW) Analysis

Identify all OTW patterns:

| Module | OTW Type | `init` Signature | OTW Consumed? | Package Upgrade Safe? |
|--------|----------|-----------------|---------------|----------------------|
| {mod} | `{MODULE_NAME}` (uppercase) | `init(otw: MODULE_NAME, ctx: &mut TxContext)` | YES/NO | YES/NO |

**Sui OTW rules**:
- OTW type name MUST match the module name in UPPERCASE.
- OTW MUST have `drop` ability (and typically no other abilities).
- OTW is automatically created by the Sui runtime and passed to `init` on module publish.
- OTW MUST be consumed in `init` (typically passed to `coin::create_currency` or similar).

**Security checks**:
- [ ] Does the OTW have ONLY `drop` ability? If it has `copy` -> can be duplicated (should be impossible due to Sui's OTW rules, but verify). If it has `store` -> can be persisted past `init` -> FINDING.
- [ ] Is the OTW consumed (used as a move value, not just referenced) in `init`? If stored instead of consumed -> it can be reused.
- [ ] **Package upgrade**: Sui package upgrades do NOT re-run `init`. Is the protocol relying on `init` for setup that should be repeatable? If the module uses OTW to create a `TreasuryCap` or `Publisher`, those are one-time-only.
- [ ] Can the OTW check be bypassed? Functions that accept `T: drop` as a witness without verifying it is the actual OTW type -> can be called with any `drop`-able type.

### 4a. OTW Verification Pattern

Check if the protocol uses `sui::types::is_one_time_witness<T>()` to verify OTW:

| Function | Accepts Generic Witness? | OTW Verification? | Bypass Possible? |
|----------|------------------------|-------------------|-----------------|
| {func} | `<T: drop>(witness: T)` | `is_one_time_witness(&witness)` / NO | YES/NO |

**Rule**: Any public function that accepts a generic witness `<T: drop>` without calling `is_one_time_witness` can be called with any droppable type, not just the actual OTW. This is a HIGH finding if the function creates currencies, capabilities, or other privileged objects.

## 5. Generic Type Confusion Attacks

Model attacks where an attacker substitutes an unexpected type:

### 5a. Function-Level Type Confusion

For each public generic function:
```
Can an attacker call function<MaliciousType>() where the protocol expects function<ExpectedType>()?
1. What type does the protocol intend?
2. What constraints prevent substitution?
3. What happens if a different type is passed?
```

| Function | Expected Type | Constraint | Substitute Possible? | Impact |
|----------|--------------|-----------|---------------------|--------|
| {func} | `SUI` | none (just `<T>`) | YES -- any type | {impact} |
| {func} | `USDC` | `<T: store>` | YES -- any `store` type | {impact} |
| {func} | specific coin | runtime check on `CoinMetadata` | NO | N/A |

### 5b. Struct-Level Type Confusion

For each generic struct:
```
Pool<T> { balance: Balance<T>, ... }

Can an attacker create Pool<FakeToken> and interact with Pool<RealToken>'s functions?
```

**Check**: Does the protocol use type parameters to distinguish pools/vaults? If yes:
- Are operations on `Pool<A>` and `Pool<B>` fully isolated?
- Can an attacker drain `Pool<A>` by exploiting `Pool<FakeA>`?
- Is there a registry/mapping that validates the type parameter? (e.g., `Table<TypeName, PoolConfig>`)

## 6. Coin/Balance Type Safety

Specific analysis for `Coin<T>` and `Balance<T>` patterns:

### 6a. Coin Type Verification

| Function | Accepts `Coin<T>` | T Verified? | Verification Method | Bypass? |
|----------|-------------------|-------------|--------------------|---------:|
| {func} | YES | YES/NO | {method or NONE} | YES/NO |

**Sui Coin safety model**:
- `Coin<T>` is parameterized by the coin type `T`.
- Creating `Coin<T>` requires a `TreasuryCap<T>`, which is created via OTW in `init`.
- An attacker CANNOT create `Coin<SUI>` because they don't have `TreasuryCap<SUI>`.
- But an attacker CAN create `Coin<ATTACKER_TOKEN>` and pass it to a function expecting `Coin<T>` if T is generic.

**Checks**:
- [ ] Do functions that handle coins use specific types (`Coin<SUI>`) or generic (`Coin<T>`)?
- [ ] If generic: is T validated against an allowed set?
- [ ] Can `Balance<FakeToken>` be joined with `Balance<RealToken>`? (NO -- type system prevents this. But verify no unsafe transmutation exists.)
- [ ] Are `Coin` split/merge operations type-safe? (`coin::split` preserves T.)

### 6b. Balance Accounting Type Safety

| Operation | Input Type | Output Type | Type Preserved? | Accounting Impact |
|-----------|-----------|-------------|----------------|------------------|
| deposit | `Coin<T>` | `Balance<T>` (internal) | YES/NO | {impact if mismatch} |
| withdraw | `Balance<T>` (internal) | `Coin<T>` | YES/NO | {impact if mismatch} |
| swap | `Coin<A>` -> `Coin<B>` | both types | YES/NO | {impact if mismatch} |

**Check**: At every point where `Balance<T>` is converted to/from `Coin<T>`, is the type parameter `T` consistent? The compiler enforces this for concrete types, but for generic functions operating on `Balance<T>`, trace that T remains the same throughout the flow.

## 7. Publisher and Package Authority

Analyze `Publisher` object usage:

| Module | Publisher Created? | Used For | Stored/Shared? | Transfer Restricted? |
|--------|-------------------|----------|---------------|---------------------|
| {mod} | YES/NO | {display, transfer policy, etc.} | {how stored} | YES/NO |

**Security checks**:
- `Publisher` proves package authorship. Functions that accept `&Publisher` trust the caller is the package publisher.
- [ ] Is `Publisher` stored in a shared object (accessible to anyone with the right reference)?
- [ ] Can `Publisher` be transferred to a malicious actor?
- [ ] Are there functions that accept `Publisher` from external callers? (These trust the caller is a publisher.)
- [ ] **Package upgrade**: After an upgrade, the original `Publisher` remains valid. Does the protocol account for this?

## Finding Template

```markdown
**ID**: [TS-N]
**Severity**: [CRITICAL if coin forgery/capability bypass, HIGH if type confusion with value, MEDIUM if witness issue]
**Step Execution**: check1,2,3,4,5,6,7 | X(reasons) | ?(uncertain)
**Rules Applied**: [R4:Y, R5:Y, R10:Y, ...]
**Depth Evidence**: [VARIATION:T=FakeToken vs T=SUI], [TRACE:generic_fn<Attacker>->state_corruption]
**Location**: module::function
**Title**: [Type safety issue] in [function] enables [attack/bypass]
**Description**: [Specific type parameter exploitation path with concrete substitute type]
**Impact**: [Unauthorized coin minting, capability forgery, pool drainage, accounting corruption]
```

---

## Step Execution Checklist (MANDATORY)

> **CRITICAL**: You MUST report completion status for ALL sections. Findings with incomplete sections will be flagged for depth review.

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1. Generic Function Inventory | YES | Y/X/? | All modules |
| 2. Type Parameter Constraint Analysis | YES | Y/X/? | |
| 2c. Phantom Type Correctness | IF phantom params | Y/X(N/A)/? | |
| 3. Type Witness Pattern Audit | IF witness patterns | Y/X(N/A)/? | |
| 3a. Witness Forgery Check | IF witness patterns | Y/X(N/A)/? | |
| 4. OTW Analysis | IF `init` with witness | Y/X(N/A)/? | **HIGH PRIORITY** |
| 4a. OTW Verification Pattern | IF generic witness functions | Y/X(N/A)/? | |
| 5. Generic Type Confusion Attacks | YES | Y/X/? | |
| 5b. Struct-Level Type Confusion | IF generic structs | Y/X(N/A)/? | |
| 6. Coin/Balance Type Safety | IF Coin/Balance used | Y/X(N/A)/? | **HIGH PRIORITY** |
| 6b. Balance Accounting Type Safety | IF Balance used | Y/X(N/A)/? | |
| 7. Publisher and Package Authority | IF Publisher used | Y/X(N/A)/? | |

### Cross-Reference Markers

**After Section 3** (Witness Pattern Audit):
- Cross-reference with ABILITY_ANALYSIS Section 4 (Capability Pattern Audit) -- witnesses often gate capabilities
- IF witness is forgeable -> escalate to CRITICAL and cross-reference all functions that accept it

**After Section 4** (OTW Analysis):
- Cross-reference with ABILITY_ANALYSIS Section 8 (Module Initializer Audit) -- OTW is consumed in `init`
- IF OTW not consumed -> check if `TreasuryCap` or `Publisher` can be created multiple times

**After Section 6** (Coin/Balance Type Safety):
- Cross-reference with TOKEN_FLOW_TRACING for multi-token accounting
- IF generic coin functions lack type verification -> model type confusion attack with concrete substitute

**After Section 7** (Publisher Authority):
- IF Publisher stored in shared object -> cross-reference with SEMI_TRUSTED_ROLES (who can access it?)
- IF package upgrade possible -> document Publisher persistence across upgrades
