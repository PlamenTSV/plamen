---
name: "type-safety"
description: "Trigger Pattern Always (Aptos Move) - generic type exploitation - Inject Into Breadth agents, depth-state-trace"
---

# TYPE_SAFETY Skill

> **Trigger Pattern**: Always (Aptos Move) --- generic type exploitation
> **Inject Into**: Breadth agents, depth-state-trace

Move's type system is its primary security mechanism. Generic type parameters allow modules to be polymorphic, but incorrect or insufficient type constraints enable attackers to substitute unexpected types, bypass access control, confuse token types, or exploit phantom type assumptions. This skill audits every generic interface for type safety violations.

**STEP PRIORITY**: Steps 2 (Type Parameter Substitution) and 5 (Coin/FungibleAsset Type Confusion) are where HIGH/CRITICAL severity findings most commonly hide. Do NOT rush these steps. If constrained, skip conditional sections (3, 4) before skipping 2 or 5.

## 1. Generic Function Inventory

Enumerate ALL public, public(friend), and entry functions with generic type parameters:

| Function | Module | Type Params | Constraints | Visibility | Entry? | Who Can Call |
|----------|--------|-------------|-------------|-----------|--------|-------------|
| `withdraw<T>` | vault | T | `key` | public | YES | Any signer |
| `swap<X, Y>` | dex | X, Y | `store` | public | YES | Any signer |

**MANDATORY GREP**: Search all `.move` files for `fun .*<` to find every generic function. Include internal (`fun`), `public(friend) fun`, `public fun`, and `public entry fun`.

For each generic function, additionally note:
- Does the function create, destroy, or transfer instances of the generic type?
- Does the function make assumptions about the generic type beyond its constraints? (e.g., assuming T is a coin type when the constraint is only `store`)
- Is the generic parameter used as a phantom/tag or does the function operate on actual instances of T?

## 2. Type Parameter Substitution Analysis

For each generic function identified in Step 1, analyze what happens when an attacker substitutes an unexpected type:

### 2a. Substitution Attack Table

| Function | Type Param | Expected Type | Attacker Substitutes | Guard Against Wrong Type? | Impact |
|----------|-----------|---------------|---------------------|--------------------------|--------|
| `withdraw<T>(store)` | T | RealCoin | FakeCoin (attacker-defined) | YES --- {mechanism} / NO | {impact} |

**Attack methodology per function**:

1. **Identify expected type**: What type does the protocol developer intend callers to use? This is often documented but NOT enforced at the type level.
2. **Check enforcement**: Is there an on-chain mechanism that restricts T to the expected type? Common mechanisms:
   - Registered type list (module stores `TypeInfo` and checks against it)
   - Type witness parameter (function also requires `&TypeWitness<T>`)
   - Module-level resource check (`assert!(exists<Pool<T>>(@protocol), E_INVALID_TYPE)`)
   - `coin::is_coin_initialized<T>()` check
   - Signer-of-defining-module pattern (only the module that defines T can call)
3. **If NO enforcement**: What happens if attacker creates `module attacker::fake { struct FakeCoin has store {} }` and calls `withdraw<FakeCoin>()`?

### 2b. Cross-Pool / Cross-Market Type Confusion

For protocols with pools, markets, or vaults parameterized by type:

| Pool/Market | Type Parameter | Can Attacker Create Pool With Arbitrary Type? | Impact If Confusion |
|-------------|---------------|----------------------------------------------|---------------------|
| `Pool<T>` | T | YES --- anyone can call `create_pool<T>()` / NO | {drain, mispricing, accounting error} |

**Check**: If Pool<RealCoin> and Pool<FakeCoin> exist, can operations on one affect the other? Common issues:
- Shared global state accessed by both pools
- Price oracle shared between pools (attacker manipulates FakeCoin price, affects RealCoin pool)
- Reward distribution computed across all pools regardless of type

Tag: `[TRACE:substitute T=FakeCoin → {function} → {bypass/confusion} → impact: {X}]`

## 3. Phantom Type Audit

For structs with phantom type parameters (`phantom T`):

### 3a. Phantom Type Inventory

| Struct | Phantom Param | Purpose | Runtime Impact of T | Can T Be Forged? |
|--------|--------------|---------|--------------------|--------------------|
| `Pool<phantom CoinType>` | CoinType | Type-tag discrimination | None (phantom) | {analysis} |

**Phantom type rules in Move**:
- Phantom type parameters do NOT affect runtime representation --- two structs with different phantom types have the same memory layout.
- Phantom types are used for type-level tagging: `Pool<USDC>` vs `Pool<WETH>` are different types at the Move level but identical at the bytecode level.
- The compiler enforces that phantom types are not used in non-phantom positions.

**Check for each phantom type**:
1. Is the phantom parameter used ONLY for type discrimination (correct use)?
2. Does any function extract or operate on the phantom type at runtime? (should be impossible by compiler, but verify no workarounds)
3. Can an attacker create a struct with a phantom type that aliases an existing legitimate phantom type? (e.g., creating `Pool<AttackerCoin>` that interacts with `Pool<USDC>` state)
4. Are phantom type parameters properly propagated through nested generics? (`Wrapper<phantom T>` containing `Inner<T>` --- is T phantom in Inner too?)

### 3b. Phantom Type Bypass Patterns

| Pattern | Risk | Check |
|---------|------|-------|
| Phantom used for access control | Medium | Can attacker define their own type to bypass access gate? |
| Phantom used for pool isolation | High | Does pool isolation rely solely on phantom type discrimination? |
| Phantom type in event emission | Low | Can attacker emit events with spoofed phantom types for off-chain confusion? |

## 4. Type Witness Pattern

For functions that accept type witnesses:

### 4a. Witness Inventory

| Witness Struct | Creating Module | Who Can Create? | Functions That Accept It | Properly Gated? |
|---------------|----------------|----------------|------------------------|-----------------|
| `TypeWitness<T>` | {module} | {analysis} | {list} | YES/NO |

**Type witness pattern** is Move's equivalent of capability-based access control at the type level. A type witness is a struct that can only be created by the module that defines the associated type. Functions that require a witness parameter are restricted to callers authorized by that module.

**Check for each witness**:
1. Is the witness struct defined in the SAME module as the type it witnesses? If not, the witness can be created by anyone who imports the witness module.
2. Does the witness have `drop`? If yes, it can be created once and reused --- is this intended?
3. Does the witness have `copy`? If yes, it can be duplicated --- does this break single-use assumptions?
4. Does the witness have `store`? If yes, it can be persisted --- can an attacker store a witness and replay it later?
5. Is witness creation gated by signer checks or capability pattern? Or can any function in the defining module create it?

### 4b. Witness Forgery Analysis

For each witness used for access control:

```
1. TypeWitness<T> is required by function F
2. TypeWitness<T> can be created by: {list of functions/modules}
3. Can attacker reach a creation path? {YES/NO --- trace}
4. If YES: attacker creates witness and calls F with unauthorized type T
5. Impact: {unauthorized operation}
```

## 5. Coin/FungibleAsset Type Confusion

For all functions that handle `Coin<T>` or `FungibleAsset`:

### 5a. Coin Type Enforcement

| Function | Accepts | Type Restriction | Enforcement Mechanism | Bypass Possible? |
|----------|---------|-----------------|----------------------|-----------------|
| `deposit<T>(coin: Coin<T>)` | Coin<T> | T must be registered | `assert!(is_registered<T>())` | {analysis} |

**Check for each coin-handling function**:
1. Does the function verify that T is the expected coin type? Or does it accept ANY `Coin<T>`?
2. If the function interacts with a pool/vault typed by T, does it verify the coin type matches the pool type?
3. Can an attacker deposit `Coin<FakeCoin>` and withdraw `Coin<RealCoin>`?
4. For multi-coin functions (`swap<X, Y>`): are X and Y validated to be a supported pair? Can attacker swap between arbitrary types?

### 5b. FungibleAsset Metadata Confusion

For protocols using the Aptos Fungible Asset standard:

| Function | Metadata Check | Object Address Validated? | Impact If Wrong Metadata |
|----------|---------------|--------------------------|--------------------------|
| {function} | YES --- `assert!(metadata == expected)` / NO | YES/NO | {wrong asset deposited/withdrawn} |

**Aptos FA-specific checks**:
1. `FungibleAsset` is NOT parameterized by type --- it uses a metadata object address for discrimination. This means type-level enforcement does NOT apply. All FungibleAssets have the same Move type.
2. Does the function verify the metadata object matches the expected asset? If not, any FungibleAsset can be passed.
3. Can an attacker create a FungibleAsset with spoofed metadata (same name/symbol as a legitimate asset)?
4. Are `FungibleStore` addresses properly validated when reading balances?

Tag: `[TRACE:deposit FakeCoin to Pool<RealCoin> → withdraw RealCoin → drain pool]`

### 5c. Mixed Standard Confusion

For protocols that handle BOTH `Coin<T>` and `FungibleAsset`:

| Operation | Which Standard Used? | Consistent? | Can Attacker Force Wrong Standard? |
|-----------|---------------------|-------------|-----------------------------------|
| deposit | Coin<T> | --- | --- |
| withdraw | FungibleAsset | MISMATCH | {analysis} |

**Check**: If deposit uses `Coin<T>` but withdraw uses `FungibleAsset` (or vice versa), is the accounting consistent? The Aptos framework provides conversion between `Coin<T>` and `FungibleAsset`, but the conversion path may not be symmetric or may bypass module-level accounting.

## 6. Module Type Authority

Only the module that defines a struct can create instances of it. This is Move's module encapsulation guarantee. Audit for violations:

### 6a. Instance Creation Audit

| Struct | Defining Module | Public Functions That Return New Instances | Should Creation Be Public? |
|--------|----------------|------------------------------------------|--------------------------|
| {name} | {module} | {list or NONE} | YES/NO --- {reason} |

**Check for each struct**:
1. Does ANY `public` or `public(friend)` function return a newly created instance of this struct?
2. If yes, should external callers be able to obtain new instances? For value-bearing structs (coins, shares, receipts), uncontrolled creation = minting vulnerability.
3. For structs used as capabilities or proofs: is there a public function that creates and returns them to arbitrary callers?
4. For `friend` functions that create instances: are ALL friend modules trusted to create instances responsibly?

### 6b. Friend Module Trust Analysis

| Module | Friend Modules | What Friends Can Create | Trust Justified? |
|--------|---------------|------------------------|-----------------|
| {module} | {friends list} | {structs accessible via friend functions} | {analysis} |

**Check**: The `friend` declaration grants the friend module full access to `public(friend)` functions, including creation functions. If a friend module has a vulnerability, it can be used to mint/create unauthorized instances.

**MANDATORY**: For each friend relationship, verify: if the friend module is compromised (has a vulnerability), what is the maximum damage to the declaring module? If friend can create value-bearing structs → severity minimum HIGH.

## Finding Template

When this skill identifies an issue:

```markdown
**ID**: [TS-N]
**Severity**: [based on type confusion impact --- fund loss from wrong type = Critical]
**Step Execution**: check1,2,3,4,5,6 | X(reasons) | ?(uncertain)
**Rules Applied**: [R1:Y, R4:Y, R5:Y, R10:Y]
**Depth Evidence**: [TRACE:substitute T=X → bypass → impact], [BOUNDARY:type=FakeCoin]
**Location**: module::function (source_file.move:LineN)
**Title**: [Function] accepts arbitrary type [T] without [validation], enabling [type confusion/drain/forgery]
**Description**: [Trace from attacker type substitution through function logic to impact]
**Impact**: [Fund drain, unauthorized minting, accounting corruption, pool confusion]
```

---

## Step Execution Checklist (MANDATORY)

> **CRITICAL**: You MUST report completion status for ALL sections. Steps 2 and 5 are highest priority.

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1. Generic Function Inventory | **YES** | Y/X/? | **MANDATORY** --- grep ALL .move files |
| 2. Type Parameter Substitution | **YES** | Y/X/? | **MANDATORY** --- highest-severity source |
| 2b. Cross-Pool Type Confusion | IF pools/markets parameterized by type | Y/X(N/A)/? | |
| 3. Phantom Type Audit | IF phantom types used | Y/X(N/A)/? | |
| 4. Type Witness Pattern | IF witness pattern used | Y/X(N/A)/? | |
| 5. Coin/FA Type Confusion | **YES** | Y/X/? | **MANDATORY** --- fund loss vector |
| 5b. FungibleAsset Metadata | IF FA standard used | Y/X(N/A)/? | Metadata validation |
| 5c. Mixed Standard Confusion | IF both Coin and FA used | Y/X(N/A)/? | |
| 6. Module Type Authority | YES | Y/X/? | Creation function audit |
| 6b. Friend Module Trust | IF friend declarations exist | Y/X(N/A)/? | Friend compromise analysis |

### Cross-Reference Markers

**After Section 2** (Type Parameter Substitution):
- IF type substitution enables unauthorized access -> cross-reference with `ABILITY_ANALYSIS.md` Section 7 for ability constraint gaps
- IF no enforcement mechanism found -> severity minimum HIGH for value-handling functions

**After Section 5** (Coin/FA Type Confusion):
- Cross-reference with token flow analysis for entry/exit point type validation
- IF FungibleAsset used without metadata check -> severity minimum HIGH (any FA can be deposited)
- IF mixed Coin + FA standards -> verify accounting consistency across standards

**After Section 6** (Module Type Authority):
- IF public creation function for value-bearing struct -> severity minimum CRITICAL (unauthorized minting)
- IF friend module has known vulnerability -> escalate all friend-accessible creation to HIGH minimum

### Mandatory Forced Output

For Sections 2 and 5, you MUST produce output even if no issues found:

**Section 2 Output** (always required):
```markdown
### 2. Type Parameter Substitution Analysis
| Function | Type Param | Expected Type | Enforcement | Substitution Blocked? |
|----------|-----------|---------------|-------------|----------------------|
| {function} | T | {expected} | {mechanism or NONE} | YES/NO |

**If enforcement = NONE for any value-handling function**: Finding verdict minimum PARTIAL.
```

**Section 5 Output** (always required):
```markdown
### 5. Coin/FungibleAsset Type Confusion
| Function | Standard | Type Restriction | Enforcement | Bypass Possible? |
|----------|---------|-----------------|-------------|-----------------|
| {function} | Coin/FA | {restriction} | {mechanism} | YES/NO |

**If ANY coin-handling function lacks type enforcement**: Verdict CONFIRMED, severity based on fund impact.
```
