---
name: "bit-shift-safety"
description: "Trigger Pattern Always (Sui Move) -- Move VM aborts on shift = bit width - Inject Into Breadth agents, depth-edge-case"
---

# BIT_SHIFT_SAFETY Skill

> **Trigger Pattern**: Always (Sui Move) -- Move VM aborts on shift >= bit width
> **Inject Into**: Breadth agents, depth-edge-case

For every bit shift operation in the protocol:

**BACKGROUND**: The Move VM (shared by Sui and Aptos) aborts the entire transaction if a bit shift operand equals or exceeds the bit width of the type. For `u64`, shifting by 64 or more aborts. For `u128`, shifting by 128 or more aborts. This is NOT a revert with an error code -- it is a VM abort that cannot be caught. On Sui, a PTB (Programmable Transaction Block) abort means ALL commands in the PTB fail, and shared objects that were locked for the transaction are released without state changes.

## 1. Shift Operation Inventory

Enumerate ALL bit shift operations (`<<` and `>>`) across all modules:

| Module | Function | Line | Operation | Type | Bit Width | Shift Amount Source | Validated? |
|--------|----------|------|-----------|------|-----------|--------------------|-----------:|
| {mod} | {func} | {L} | `<<` / `>>` | u8/u64/u128/u256 | 8/64/128/256 | {literal/parameter/computed} | YES/NO |

**Grep pattern**: Search all `.move` files for `<<` and `>>` operators.

**Type-to-width mapping**:
| Type | Max Safe Shift |
|------|---------------|
| `u8` | 7 |
| `u64` | 63 |
| `u128` | 127 |
| `u256` | 255 |

## 2. Shift Amount Source Classification

For each shift operation, classify the shift amount source:

### 2a. Literal Shifts (Low Risk)
```move
let x = value << 32;  // Literal: always safe if < bit width
```
**Check**: Is the literal < bit width of the type? If yes -> SAFE. If no -> compilation may succeed but runtime aborts.

### 2b. Parameter-Derived Shifts (Medium Risk)
```move
public fun shift_by(value: u64, amount: u8): u64 {
    value << (amount as u8)  // Parameter: caller controls shift amount
}
```
**Check**: Is the `amount` parameter validated before the shift? Common patterns:
- `assert!(amount < 64, E_SHIFT_OVERFLOW)` -- explicit validation
- `amount % 64` -- wrapping (changes semantics but prevents abort)
- No validation -- FINDING

### 2c. Computed Shifts (High Risk)
```move
let shift = calculate_precision(decimals);  // Computed: depends on runtime state
let result = base << shift;
```
**Check**: Can the computation ever produce a value >= bit width? Trace the computation to its inputs. If any input is user-controlled or state-derived -> HIGH RISK.

## 3. Abort Impact Analysis

For each unvalidated shift operation, assess the abort impact:

| Function | Called By | Shared Objects Locked? | PTB Context | Abort Impact |
|----------|----------|----------------------|-------------|-------------|
| {func} | {callers} | YES/NO | {typical PTB} | {impact} |

**Sui-specific abort consequences**:
- **PTB abort**: All commands in the Programmable Transaction Block fail atomically. If the shift is in command 3 of a 5-command PTB, commands 1-2 are also rolled back.
- **Shared object locking**: If the aborting function locks shared objects (accessed via `&mut` reference), those objects are temporarily unavailable during consensus. Repeated aborts can cause transient unavailability. This is NOT permanent locking -- Sui releases locks after the transaction fails.
- **Gas consumption**: The sender pays gas for the aborted transaction up to the abort point.
- **Griefing vector**: If an attacker can trigger the abort via a public function with a user-controlled shift amount, they can grief other users by causing their PTBs to abort. This is especially impactful when the aborting function is called as part of a common user flow (deposit, swap, claim).

### 3a. Griefing Scenario Modeling

For each unvalidated shift in a public/entry function:

```
Scenario: Shift Abort Griefing
1. Attacker calls {FUNCTION} with shift amount = {BIT_WIDTH}
2. Move VM aborts the transaction
3. Impact on other users: {IMPACT}
   - If function modifies shared state: other PTBs depending on that state must retry
   - If function is part of a multi-step user flow: user loses gas + must restart
4. Attacker cost: gas for one failed transaction
5. Severity: {based on impact}
```

## 4. Common Vulnerable Patterns

### 4a. Decimal Conversion Shifts
```move
// VULNERABLE: decimals comes from token metadata, could be >= 64
let scale = 1u64 << decimals;
```
**Fix pattern**: `assert!(decimals < 64, E_INVALID_DECIMALS)` or use `math::pow(10, decimals)` instead.

### 4b. Bit Packing / Unpacking
```move
// VULNERABLE if position is not bounds-checked
let field = (packed >> position) & mask;
```
**Check**: Is `position` derived from user input or configuration? If yes and no validation -> FINDING.

### 4c. Fixed-Point Arithmetic
```move
// Common in DeFi: fixed-point multiplication with shift
let result = (a * b) >> PRECISION_BITS;
```
**Check**: Is `PRECISION_BITS` a constant? If yes and < bit width -> SAFE. If computed -> trace source.

### 4d. Loop-Based Shifts
```move
let mut i = 0;
while (i < n) {
    value = value << 1;  // Safe per iteration, but after 64 iterations value = 0 (not abort)
    i = i + 1;
};
```
**Note**: Shifting by 1 repeatedly does NOT abort (shift amount is always 1). But the value overflows silently to 0 after bit-width iterations. Check if this silent overflow causes logic errors.

## 5. Validation Pattern Verification

For each shift operation that IS validated, verify the validation is correct:

| Function | Validation | Correct? | Edge Case |
|----------|-----------|----------|-----------|
| {func} | `assert!(n < 64)` | YES | n=63 is max safe |
| {func} | `assert!(n <= 64)` | **NO** | n=64 aborts |
| {func} | `n % 64` | SAFE but semantic change | shift by 0 when n=64 |

**Common validation errors**:
- Off-by-one: `<= bit_width` instead of `< bit_width`
- Wrong bit width: validating against 64 for a `u128` shift (allows 64-127 to abort)
- Missing cast: `amount` is `u64` but shift operand must be `u8` -- does the cast truncate?

## 6. Cross-Function Shift Propagation

Trace shift amounts across function boundaries:

```
entry_function(user_input: u64)
  -> helper_a(derived_value)  // derived_value = user_input * 2
    -> helper_b(shift_amount) // shift_amount = derived_value + offset
      -> actual_shift: value << shift_amount  // Is shift_amount < bit_width?
```

**For each chain**: Can ANY combination of valid inputs to the entry function produce a shift amount >= bit width at the actual shift site? Document the full trace.

## Finding Template

```markdown
**ID**: [BS-N]
**Severity**: [HIGH if public function, MEDIUM if restricted caller, LOW if constant shift]
**Step Execution**: check1,2,3,4,5,6 | X(reasons) | ?(uncertain)
**Rules Applied**: [R4:Y, R10:Y, ...]
**Depth Evidence**: [BOUNDARY:shift=bit_width], [TRACE:user_input->shift_amount->abort]
**Location**: module::function:LineN
**Title**: Unvalidated bit shift in [function] causes VM abort on [condition]
**Description**: [Specific shift operation, source of shift amount, why it can reach bit width]
**Impact**: [Transaction abort, shared object locking, griefing potential, gas waste]
```

---

## Step Execution Checklist (MANDATORY)

> **CRITICAL**: You MUST report completion status for ALL sections. Findings with incomplete sections will be flagged for depth review.

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1. Shift Operation Inventory | YES | Y/X/? | Grep all `.move` files |
| 2. Shift Amount Source Classification | YES | Y/X/? | For each shift |
| 3. Abort Impact Analysis | IF unvalidated shifts found | Y/X(N/A)/? | |
| 3a. Griefing Scenario Modeling | IF unvalidated in public fn | Y/X(N/A)/? | |
| 4. Common Vulnerable Patterns | YES | Y/X/? | Check all 4 sub-patterns |
| 5. Validation Pattern Verification | IF validated shifts exist | Y/X(N/A)/? | Off-by-one check |
| 6. Cross-Function Shift Propagation | IF shift amount crosses functions | Y/X(N/A)/? | |

### Cross-Reference Markers

**After Section 1** (Shift Inventory):
- IF zero shift operations found -> mark skill as N/A, skip remaining sections
- IF shifts found in math/fixed-point libraries -> prioritize Section 4c

**After Section 3** (Abort Impact):
- IF abort affects shared objects -> cross-reference with ABILITY_ANALYSIS Section 2b (shared object analysis)
- IF abort is in a hot potato consumption path -> cross-reference with ABILITY_ANALYSIS Section 5 (hot potato enforcement) -- abort before consumption = permanent PTB failure

**After Section 6** (Cross-Function Propagation):
- IF any chain reaches bit width with valid inputs -> FINDING (minimum Medium)
- Tag: `[BOUNDARY:shift={bit_width}]`, `[TRACE:input_path->abort_site]`
