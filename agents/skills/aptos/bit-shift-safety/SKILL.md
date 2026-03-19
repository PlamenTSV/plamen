---
name: "bit-shift-safety"
description: "Trigger Pattern Always (Aptos Move) - Move VM aborts on shift = bit width - Inject Into Breadth agents, depth-edge-case"
---

# BIT_SHIFT_SAFETY Skill

> **Trigger Pattern**: Always (Aptos Move) --- Move VM aborts on shift >= bit width
> **Inject Into**: Breadth agents, depth-edge-case

The Move VM performs a runtime check on every bit shift operation: if the shift amount is greater than or equal to the bit width of the operand type, the transaction aborts. This is not a silent wraparound --- it is a hard abort that reverts the entire transaction. Any user-controllable or computed shift amount that can reach the bit width threshold is a denial-of-service vector.

## 1. Shift Operation Inventory

**MANDATORY GREP**: Search all `.move` files for `<<` and `>>` operators.

For each shift operation found:

| Location (file:line) | Operand Type | Bit Width | Shift Amount Source | User-Controllable? | Bounded? |
|-----------------------|-------------|-----------|--------------------|--------------------|----------|
| {file}:{line} | u8/u16/u32/u64/u128/u256 | 8/16/32/64/128/256 | constant / parameter / computed | YES/NO | YES/NO --- {how} |

**Classification of shift amount sources**:
- **Constant**: Hardcoded literal (e.g., `1 << 64`). Safe if < bit width, abort if >= bit width. Check constants that equal or exceed the bit width --- this is a compile-time-detectable bug but Move does not always catch it.
- **Parameter**: Passed into the function from a caller. Trace the call chain to determine if externally controllable.
- **Computed**: Result of arithmetic (e.g., `1 << (decimals - offset)`). Requires boundary analysis.

## 2. Shift Amount Bound Verification

For each shift operation where the shift amount is NOT a safe constant:

### 2a. Bit Width Threshold Table

| Type | Bit Width | Max Safe Shift | Abort Condition |
|------|-----------|---------------|-----------------|
| u8 | 8 | 7 | shift >= 8 |
| u16 | 16 | 15 | shift >= 16 |
| u32 | 32 | 31 | shift >= 32 |
| u64 | 64 | 63 | shift >= 64 |
| u128 | 128 | 127 | shift >= 128 |
| u256 | 256 | 255 | shift >= 256 |

### 2b. Bound Verification Per Shift

For each non-constant shift:

| Location | Shift Amount Expression | Minimum Value | Maximum Value | Exceeds Bit Width? | Guard Present? |
|----------|------------------------|---------------|---------------|-------------------|----------------|
| {location} | {expression} | {min} | {max} | YES/NO | YES --- {assert/min/if} / NO |

**Verification method**: Trace the shift amount back to its origin. For each variable in the expression:
1. What is its declared type? (constrains range)
2. Is there an `assert!()` that bounds it before the shift?
3. Is there a `min()` or `if` guard?
4. Can the variable be set by an external caller (entry function parameter, stored value set by a public function)?

Tag: `[BOUNDARY:shift_amount={val} → abort at bit_width={W}]`

## 3. Computed Shift Analysis

For shift amounts derived from arithmetic, perform boundary value analysis:

### 3a. Subtraction Underflow in Shift Amount

Pattern: `1 << (a - b)` where both `a` and `b` are unsigned integers.

| Location | Expression | Can `b > a`? | Underflow Result | Impact |
|----------|-----------|-------------|-----------------|--------|
| {location} | `1 << (decimals - 6)` | YES if decimals < 6 | Wraps to large u8/u64 → abort | DoS |

**Check**: Move unsigned subtraction aborts on underflow (no wraparound). So `a - b` where `b > a` aborts BEFORE the shift. This is a separate DoS vector (arithmetic underflow). Document both:
1. Underflow abort if `b > a`
2. Shift abort if `a - b >= bit_width`

### 3b. Addition/Multiplication Overflow in Shift Amount

Pattern: `value << (a + b)` or `value << (a * b)`

| Location | Expression | Can Sum/Product >= Bit Width? | Impact |
|----------|-----------|------------------------------|--------|
| {location} | {expression} | YES/NO --- {boundary values} | {DoS / safe} |

### 3c. Shift Result Overflow

Even if the shift amount is safe, the RESULT of the shift may overflow the type:

| Location | Expression | Operand Max Value | Shift Amount | Result Exceeds Type Max? | Impact |
|----------|-----------|-------------------|-------------|-------------------------|--------|
| {location} | `amount << decimals` | {max} | {amount} | YES/NO | {silent truncation / abort} |

**Note**: Move does NOT abort on shift result overflow --- the result is silently truncated (high bits discarded). This is a correctness bug, not a DoS bug, but can cause incorrect calculations (e.g., `1u64 << 63` = 9223372036854775808, but `3u64 << 63` = 9223372036854775808 due to truncation).

Tag: `[BOUNDARY:shift_result=truncated at type_max]`

## 4. DoS Impact Assessment

For each shift operation that can abort:

### 4a. Abort Impact Trace

| Location | Function | Entry Point? | Who Calls This? | Abort Blocks What? | Severity |
|----------|----------|-------------|----------------|--------------------|---------|
| {location} | {function} | YES/NO | {callers} | {blocked operations} | {H/M/L} |

**Trace from the aborting shift outward**:
1. Which function contains the shift?
2. Is that function called by entry functions (user-facing)?
3. Is it called in a critical path (deposit, withdraw, claim, liquidation)?
4. Can an attacker provide input that triggers the abort?
5. Does the abort affect ONLY the attacker's transaction, or does it block other users?

**Severity guide**:
- Shift in view function only -> Low (informational, no state impact)
- Shift in user's own transaction path (self-DoS only) -> Low
- Shift in shared operation (affects all users) -> Medium to High
- Shift in critical path (deposits/withdrawals blocked for all) triggered by attacker input -> High
- Shift in liquidation/price computation path -> High to Critical (can block liquidations, enable insolvency)

### 4b. Attacker-Triggerable Analysis

For shifts that can abort and are in shared/critical paths:

```
1. Attacker calls entry function F with parameter P
2. P flows through {trace} to shift operation at {location}
3. Shift amount becomes {expression} which equals {value} >= {bit_width}
4. Transaction aborts
5. Impact: {what is blocked for other users}
6. Cost to attacker: {gas cost only / requires tokens / requires role}
7. Persistence: {one-time / repeatable / permanent state corruption}
```

Tag: `[TRACE:attacker input P={val} → shift abort → {blocked_operation} DoS]`

## 5. Safe Shift Patterns

Document which shifts in the codebase follow safe patterns (for completeness and to confirm analysis coverage):

| Pattern | Example | Why Safe |
|---------|---------|----------|
| Constant shift < bit width | `1u64 << 32` | 32 < 64, always safe |
| Bounded by min() | `1 << min(amount, 63)` | Capped below bit width |
| Guarded by assert | `assert!(shift < 64, E_INVALID); val << shift` | Explicit pre-check |
| Type-constrained | `(x as u8) << 4` where x comes from a u8 field | u8 max = 255, but shift amount 4 is constant |
| Bounded by protocol invariant | `decimals` is always 6 or 8 (set once, immutable) | Document the invariant and verify immutability |

**RULE**: A shift is only "safe by protocol invariant" if the invariant is ENFORCED on-chain (assert, type constraint, immutable field set in constructor). Documentation-only invariants do NOT qualify.

## Finding Template

When this skill identifies an issue:

```markdown
**ID**: [BS-N]
**Severity**: [based on DoS scope and attacker controllability]
**Step Execution**: check1,2,3,4,5 | X(reasons) | ?(uncertain)
**Rules Applied**: [R2:Y, R4:Y, R10:Y]
**Depth Evidence**: [BOUNDARY:shift_amount={val}], [TRACE:input→abort→impact]
**Location**: module::function (source_file.move:LineN)
**Title**: Unbounded bit shift in [function] enables [DoS/incorrect calculation]
**Description**: [Trace from input to shift operation to abort/truncation to impact]
**Impact**: [What is blocked or miscalculated, who is affected, persistence]
```

---

## Step Execution Checklist (MANDATORY)

> **CRITICAL**: You MUST report completion status for ALL sections. Sections 1-2 are mechanical and must never be skipped.

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1. Shift Operation Inventory | **YES** | Y/X/? | **MANDATORY** --- grep ALL .move files |
| 2. Shift Amount Bound Verification | YES | Y/X/? | For each non-constant shift |
| 3. Computed Shift Analysis | IF computed shifts found | Y/X(N/A)/? | Subtraction underflow + result overflow |
| 3c. Shift Result Overflow | IF shifts with variable operands | Y/X(N/A)/? | Silent truncation check |
| 4. DoS Impact Assessment | IF any shift can abort | Y/X(N/A)/? | Trace to user impact |
| 4b. Attacker-Triggerable Analysis | IF abort in shared/critical path | Y/X(N/A)/? | Full attack trace |
| 5. Safe Shift Patterns | YES | Y/X/? | Confirm safe shifts for coverage |

### Cross-Reference Markers

**After Section 1** (Shift Operation Inventory):
- IF zero shifts found in codebase -> mark all sections X(N/A), write "No bit shift operations found in audited modules" and STOP
- IF shifts found -> proceed to Section 2, do NOT skip

**After Section 4** (DoS Impact Assessment):
- Cross-reference with access control analysis: can the aborting function be called permissionlessly?
- Cross-reference with oracle/price analysis: are shifts used in price computations? If yes, abort = price oracle DoS -> severity escalation
- IF shift in liquidation path -> severity minimum HIGH

**After Section 5** (Safe Shift Patterns):
- Verify: every shift from Section 1 is accounted for in EITHER Section 2 (unsafe) or Section 5 (safe)
- Any unaccounted shift -> reanalyze before finalizing
