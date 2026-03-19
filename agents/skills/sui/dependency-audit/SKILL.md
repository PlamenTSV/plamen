---
name: "dependency-audit"
description: "Trigger Pattern EXTERNAL_LIB flag (third-party Move dependencies detected in Move.toml beyond Sui framework) - Inject Into Breadth agents, depth-external"
---

# Skill: DEPENDENCY_AUDIT (Sui/Move)

> **Trigger Pattern**: EXTERNAL_LIB flag (third-party Move dependencies detected in Move.toml beyond Sui framework)
> **Inject Into**: Breadth agents, depth-external
> **Finding prefix**: `[DEP-N]`
> **Rules referenced**: R1, R4, R8, R10

Move's dependency model is package-based: `Move.toml` declares dependencies with git URLs and revisions. Unlike EVM's compiled-and-deployed model where dependencies are inlined at compile time, Sui Move packages can depend on other PUBLISHED packages (on-chain) or source packages (compiled together). Third-party math libraries, utility packages, and protocol SDKs are common dependency vectors.

**STEP PRIORITY**: Steps 3 (Critical Function Audit, especially Step 4 Math Library Audit) and 5 (Shared Object Dependencies) are where HIGH/CRITICAL severity findings most commonly hide. The Cetus hack originated from a custom math library bit shift bug. Do NOT rush these steps.

---

## Trigger Patterns

```
[dependencies]|git\s*=|subdir\s*=|rev\s*=|published-at|math|utils|library|helpers|common
```

---

## Step 1: Dependency Inventory

Parse `Move.toml` and build a complete dependency tree. Categorize:

| # | Dependency Name | Source Type | Source URL/Address | Version/Rev Pinned? | Trust Level | Upgrade Risk |
|---|----------------|------------|-------------------|---------------------|-------------|-------------|
| 1 | Sui | Framework | sui framework | Validator-controlled | TRUSTED | Framework upgrade by validators |
| 2 | MoveStdlib | Framework | std library | Validator-controlled | TRUSTED | Framework upgrade by validators |
| 3 | {third_party} | Git source | {url} | YES (rev={hash}) / NO (branch) | MUST_AUDIT | {describe} |
| 4 | {on_chain_dep} | Published | {on-chain address} | YES (version pinned) / NO | MUST_AUDIT | {describe} |
| 5 | {protocol_own} | Local path | {path} | N/A (in scope) | IN_SCOPE | N/A |

**Trust classification**:
- **TRUSTED**: Sui framework packages (`sui`, `std`). Audited by Mysten Labs, upgraded by validator governance. Minimal audit needed (but check for version-specific quirks).
- **MUST_AUDIT**: Third-party packages. MUST analyze critical functions used by the protocol.
- **IN_SCOPE**: Protocol's own packages. Full audit in main analysis.

---

## Step 2: Package Immutability Check

For each third-party dependency, assess immutability and upgrade risk:

| Dependency | Pinned to Specific Rev? | Published On-Chain? | UpgradeCap Status | Upgrade Policy | Risk |
|-----------|------------------------|--------------------|--------------------|---------------|------|
| {dep} | YES (rev: {hash}) / NO (branch: main) | YES/NO | Destroyed (immutable) / Held by {who} / UNKNOWN | {compatible/additive/dep_only/immutable} | {assess} |

**Source dependencies** (compiled together):
- Pinned to specific git revision -> code is fixed at that commit. Safe from upstream changes.
- Pinned to a branch (e.g., `main`) -> upstream pushes automatically affect next compilation. **FINDING**: unpinned dependency.
- No `rev` field -> defaults to latest on default branch. Highest risk.

**Published on-chain dependencies** (referenced via `published-at`):
- Immutable package (UpgradeCap destroyed) -> behavior cannot change. Safe.
- Package with active UpgradeCap + `compatible` policy -> behavior CAN change.
- Your package pins to a specific version at compile time. If dependency publishes V2, you still use V1.
- **Risk**: When YOU upgrade (recompile), you may pull in dependency's latest version unknowingly.

**Known upgrade history**: Has the dependency been upgraded before? How many versions exist? Frequent upgrades indicate active development but also active change risk.

**Checklist**:
- [ ] Every third-party dependency is pinned to a specific git revision (not a branch)
- [ ] Published dependencies are either immutable or their upgrade policy is documented
- [ ] No dependency uses a `latest` or `main` branch reference

---

## Step 3: Transitive Dependency Risk

Map the full dependency tree:

| Dependency A | Depends On | Dep B Audited? | Dep B Upgrade Risk | Version Conflict? |
|-------------|-----------|---------------|-------------------|------------------|
| {dep_A} | {dep_B, dep_C} | YES/NO | {describe} | YES/NO |

**Transitive dependency risks**:
- A -> B -> C: If C has vulnerability, A is affected even though A does not directly import C
- Version conflicts: If A depends on C v1 and B depends on C v2, Move compilation may fail. Sui resolves diamond dependencies by requiring all paths to agree on the same version.
- Transitive upgrade: If B upgrades and changes its dependency on C, your next recompile may pull different C code.

**If Dep B upgrades, does it affect us through Dep A?**
- Only if we recompile our package (Sui does not dynamically resolve dependencies)
- But: if Dep B is an on-chain published package that Dep A calls via CPI-equivalent, behavior changes immediately after Dep B upgrades

---

## Step 4: Math Library Audit (CRITICAL -- Cetus Precedent)

> **Historical context**: A major DeFi exploit targeted a bug in a custom bit shift helper function in a math library. This step is MANDATORY for any custom math/arithmetic library in the dependency tree.

For any custom math/arithmetic library dependency:

### 4a. Bit Shift Operation Audit (MR2)

Trace ALL bit shift operations (`<<`, `>>`) in the math library:

| # | Function | Shift Operation | Shift Amount Source | Bounds Checked? | Overflow Possible? |
|---|----------|----------------|--------------------|-----------------|--------------------|
| 1 | {func} | `value << amount` | {parameter / constant / computed} | YES/NO | YES/NO |

**Move bit shift rules**:
- `<<` and `>>` do NOT abort if shift amount >= bit width -- they produce 0
- Custom bit shift helpers MUST validate shift amount < bit width
- If shift amount comes from user input or computation, it must be bounds-checked

**Specific checks**:
- [ ] Are ALL shift amounts validated to be < bit width of the operand type?
- [ ] Do custom bit shift helpers correctly handle edge cases (shift amount >= bit width, zero inputs, overflow)?
- [ ] Can intermediate computation produce a shift amount >= bit width?
- [ ] Are there any bit manipulation patterns that assume shift produces a specific non-zero result?

### 4b. Overflow/Underflow Audit

| # | Function | Operation | Input Range | Overflow Possible? | Handling |
|---|----------|-----------|------------|--------------------|---------|
| 1 | {func} | `a * b` | {describe} | YES if a,b > sqrt(MAX_U128) | abort (safe) / wrapping (DANGEROUS) |

**Move arithmetic safety**:
- Default `+`, `-`, `*` abort on overflow/underflow -- safe
- But: custom math libraries may use bitwise operations to implement unchecked arithmetic for gas optimization
- `as` casts between integer types abort on overflow (e.g., `(x as u64)` where x > MAX_U64)
- Fixed-point: `(a * b) / SCALE` -- intermediate `a * b` may overflow u128 even if final result fits in u64

### 4c. Rounding and Precision

| # | Function | Rounding Direction | Consistent? | Impact if Wrong Direction |
|---|----------|-------------------|-------------|--------------------------|
| 1 | {mul_div} | {up / down / nearest / truncation} | YES/NO | {describe: e.g., attacker extracts extra dust per operation} |

**Check**: For every division operation in the math library:
- Is rounding direction documented?
- Is rounding direction consistent with how the protocol uses the result?
- Can rounding errors accumulate across many operations?

---

## Step 5: Shared Object Dependencies

If the protocol uses shared objects from external packages:

| External Shared Object | Package | Our Functions That Access It | What We Read/Write | Behavior Change If Package Upgrades? |
|-----------------------|---------|----------------------------|-------------------|--------------------------------------|
| {oracle_obj} | {oracle_pkg} | {our_module::read_price} | READ price field | YES -- oracle upgrade could change price format |
| {dex_pool} | {dex_pkg} | {our_module::swap} | WRITE (swap) | YES -- DEX upgrade could change swap logic |

**Are we validating shared object state after external calls?**
- After reading price from external oracle shared object: do we validate freshness? bounds? format?
- After calling external DEX swap: do we validate received amount? slippage?
- If external package upgrades and changes shared object behavior, our code reads different data without any change on our side.

**Key risk**: External package with `compatible` upgrade policy can change function implementations. Our calls to those functions produce different results after upgrade, with no code change or compilation on our side.

---

## Step 6: Interface Compatibility

Could new abort conditions be added in dependency upgrades?

| Dependency Function | Current Abort Conditions | Possible New Abort Conditions | Impact on Our Protocol |
|-------------------|------------------------|-----------------------------|----------------------|
| {dep::func} | {list current aborts} | {what upgrades could add} | {describe: e.g., our transaction aborts unexpectedly} |

**Check**:
- If a dependency function currently never aborts but an upgrade adds an abort condition -> our protocol's transactions may start failing
- If a dependency function changes its return value semantics (e.g., rounding direction changes) -> our calculations become incorrect
- If a dependency adds new type constraints -> our generic calls may no longer compile on next recompile

---

## Key Questions (Must Answer All)

1. **Pinning**: Are all third-party dependencies pinned to specific git revisions?
2. **Critical functions**: For each math/utility function from a dependency, does it handle edge cases correctly?
3. **Bit shifts**: Are ALL bit shift operations in math libraries bounds-checked? (Cetus precedent)
4. **Upgrade risk**: Can any dependency change behavior without the protocol team's knowledge?
5. **Shared objects**: If we use shared objects from external packages, can their behavior change via upgrade?
6. **Transitive**: Are there transitive dependencies, and are they audited?

---

## Common False Positives

1. **Framework dependencies**: `sui::*` and `std::*` are validator-controlled and well-audited. Findings about framework functions are rarely valid unless version-specific.
2. **Pinned and immutable**: Dependency pinned to specific rev AND on-chain package is immutable -> no upgrade risk.
3. **Unused imports**: Dependency imported but no functions actually called -> no runtime risk.
4. **Well-known libraries**: Widely-used and audited libraries with specific rev pinning -> lower risk, but STILL check edge cases for specific functions used.

---

## Output Schema

```markdown
## Finding [DEP-N]: Title

**Verdict**: CONFIRMED / PARTIAL / REFUTED / CONTESTED
**Step Execution**: check1,2,3,4,5,6 | skip(reason) | uncertain
**Rules Applied**: [R1:___, R4:___, R8:___, R10:___]
**Severity**: Critical/High/Medium/Low/Info
**Location**: Move.toml or sources/{module}.move:LineN (where dep function is called)

**Dependency**: {dependency_name}
**Function**: {specific function if applicable}
**Issue Type**: UNPINNED_VERSION / ARITHMETIC_UNSAFE / BIT_SHIFT_UNSAFE / EDGE_CASE_UNHANDLED / SPEC_MISMATCH / TRANSITIVE_RISK / UPGRADE_RISK / SHARED_OBJECT_DEP

**Description**: What is wrong
**Impact**: What can happen (incorrect calculation, overflow, unexpected abort, supply manipulation)
**Evidence**: Code showing the issue
**Recommendation**: How to fix (pin version, add validation, use alternative, wrap with checks)
```

---

## Step Execution Checklist (MANDATORY)

| Step | Required | Completed? | Notes |
|------|----------|------------|-------|
| 1. Dependency Inventory | YES | | All deps from Move.toml enumerated |
| 2. Package Immutability Check | YES | | Pinning and on-chain policy for each dep |
| 3. Transitive Dependency Risk | YES | | Full dependency tree mapped |
| 4. Math Library Audit | IF math/arithmetic deps exist | | **HIGH PRIORITY** -- Cetus precedent |
| 4a. Bit Shift Operation Audit | IF bit shifts in math deps | | Every shift bounds-checked |
| 4b. Overflow/Underflow Audit | IF math deps | | Checked vs unchecked arithmetic |
| 4c. Rounding and Precision | IF division in math deps | | Direction documented and consistent |
| 5. Shared Object Dependencies | IF external shared objects used | | Behavior change on upgrade |
| 6. Interface Compatibility | IF upgradeable deps | | New abort conditions, return value changes |

### Cross-Reference Markers

**After Step 2**: If any dependency unpinned -> immediate Informational/Low finding.

**After Step 4**: If math library has unchecked bit shifts -> cross-reference with BIT_SHIFT_SAFETY skill for protocol-level impact analysis.

**After Step 5**: If shared object dependencies from upgradeable packages -> cross-reference with PACKAGE_VERSION_SAFETY Step 3 and EXTERNAL_PRECONDITION_AUDIT Step 3b.

If any step skipped, document valid reason (N/A, no third-party deps, framework-only, no math functions used).
