---
name: "integration-hazard-research"
description: "Protocol Type Trigger NAMED_EXTERNAL_PROTOCOL (detected when recon finds import/interface for an identifiable external protocol — not standard libraries). Researches known integration hazards of the target protocol."
---

# Injectable Skill: Integration Hazard Research

> **Protocol Type Trigger**: `NAMED_EXTERNAL_PROTOCOL` — detected when recon identifies imports or interface calls to a named external protocol (Uniswap, Aave, Balancer, Compound, Curve, Chainlink, Lido, MakerDAO, etc.) that is NOT a standard library (OpenZeppelin, solmate, solady) and NOT the protocol under audit itself.
> **Inject Into**: depth-external agent
> **Language**: All chains (EVM primary; Solana/Aptos/Sui when integrating with named on-chain protocols)
> **Finding prefix**: `[IHR-N]`
> **Added in**: v1.1.5

## Worker Application Contract

This skill is executed by one already-launched depth-external worker. It adds a
dependency-evidence pass (Section 0) before that worker's existing code
analysis. Do not spawn or delegate work. The runtime prompt's exact input
projection and single output allowlist override every illustrative filename in
this methodology.

When decomposing the assigned investigation:
- Section 0 (research): produces a hazard catalog that informs all of depth-external's existing Sections 1-4
- Section 1 (third-party race): extends depth-external Section 1 (side effects)
- Section 2 (state TOCTOU): extends depth-external Section 4 (governance/parameter change)

## When This Skill Activates

Recon Agent 3 detects named external protocol imports during TASK 6 pattern scanning. Indicators:
- Named protocol interfaces: `IUniswapV2Router`, `IUniswapV3Pool`, `IBalancerVault`, `IPool`, `IAToken`, `ICToken`, `ILendingPool`, `ICurvePool`, `IChainlinkAggregator`, `IStETH`
- Named protocol library imports: `@uniswap/`, `@aave/`, `@balancer-labs/`, `@chainlink/`, `@openzeppelin/` (only when calling protocol-specific functions, not generic utilities)
- Solana: CPI targets to known program IDs (Jupiter, Marinade, Raydium, Orca, Drift)
- Sui: external package calls to known protocols (Cetus, DeepBook, Suilend, NAVI)
- Aptos: external module calls to known protocols (Thala, Echelon, Liquidswap, PancakeSwap)
- Soroban: cross-contract calls to known protocols (SoroSwap, Blend Protocol, Phoenix DEX, Aqua Network, OrbitCDP)

The flag records which protocols were detected: `NAMED_EXTERNAL_PROTOCOL: [Uniswap V3, Chainlink]`

---

## Processing Protocol (MANDATORY)

For each section below, execute in order:
1. **ENUMERATE targets**: List every entity the section applies to (external protocols, hazard catalog entries, race condition candidates, TOCTOU pairs) as a numbered list before analysis begins.
2. **PROCESS exhaustively**: Analyze each numbered entity. Mark each "DONE" or "N/A (reason)" before moving to the next.
3. **COVERAGE GATE**: Count enumerated vs processed. If any entity lacks a marker, process it before proceeding to the next section.

## 0. Target Protocol Hazard Research

For EACH named external protocol detected by recon:

### 0a. Consume the Authenticated Dependency Projection (PRIMARY — MANDATORY)

Use only the exact authenticated
`scratchpad:external_dependency_research.md` input listed in the runtime
prompt's model-visible PhaseIO projection. Never discover, infer, or open a
producer, intermediate, home-directory copy, or alternate research artifact.
Do not invoke network, precedent, vulnerability-database, shell, or package
tools from this filesystem-only depth worker.

For each target protocol/dependency, find its row in that exact projection:
`Dependency | Integration Surface (file:line) | Assumed Behavior (as coded) |
Real Behavior (researched) | Source (URL + fetch date) | Conformance
MATCH/MISMATCH/CHECK | Fetch Status OK/FETCH_FAILED:reason`. Use only its Real
Behavior / Conformance columns as the hazard-catalog input for Section 0c.

### 0b. Escalate Uncovered Surfaces — Do Not Guess (MANDATORY)

If the authenticated projection is absent from the runtime input list,
unreadable, missing a dependency, or contains `Fetch Status: FETCH_FAILED`, do
not guess the real behavior and do not silently treat the floor catalog as
research. Emit, inside the assigned findings output, one typed escalation line
per uncovered surface:

```
NEEDS_DEPENDENCY_RESEARCH: <dependency>:<file:line>: <what you need to know>
```

Then proceed under the assumed WORST-CASE realistic external condition per the
driver-bound finding-format rules, tagging the finding
`[EXTERNAL-ASSUMPTION: <assumed condition>]`. The typed escalation is the only
valid fallback for missing dependency evidence in this worker.

### 0c. Compile Hazard Catalog

| Target Protocol | Known Integration Hazard | Severity | Root Cause | Source | Applicable to This Integration? |
|----------------|------------------------|----------|------------|--------|-------------------------------|
| {protocol} | {hazard title} | {sev} | {brief root cause} | {authenticated projection row / URL} | YES / NO / CHECK |

**Applicability criteria** (same as FORK_ANCESTRY):
- YES: The audited code calls the function or reads the state involved in this hazard
- NO: The audited code does not interact with the affected function/state (document why)
- CHECK: Cannot determine without deeper analysis — flag for depth trace

### 0c-bis. Asset-Form Delivery Check (MANDATORY for every bridge/gateway/router callback + outbound deposit/withdraw)

Cross-chain gateways frequently deliver the gas token in a DIFFERENT FORM than the handler assumes — native vs wrapped (e.g. ETH vs WETH). This is an asset-FORM mismatch, distinct from the asset-IDENTITY (declared-output-token vs delivered-token) mismatch. For EACH inbound callback (`onCall`/`onReceive`/`onRevert`/router callback) and EACH outbound `deposit`/`withdraw`:
1. From the external protocol's docs/source, determine whether it DELIVERS/EXPECTS the asset in **NATIVE or WRAPPED** form (many gas-token bridges auto-unwrap to native on delivery and auto-wrap on send).
2. Assert the handler's FIRST value-moving op matches that form: a wrapped-ERC20 `approve`/`transferFrom`/`swap` requires the asset to already be wrapped; a `.call{value:}`/native send requires it to be native.
3. **RED FLAG → emit a CHECK candidate** (never a silent `UNVERIFIED`): the callback names a wrapped-token address as the asset param but the handler moves it via ERC20 `approve`/`transfer` with NO `deposit{value:}`/`withdraw()` reconciliation (or vice-versa). The missing inbound native→wrapped (or wrapped→native) conversion is a candidate asset-form mismatch — verify reachability and impact.
4. If the delivery form cannot be confirmed from docs/source, escalate to a CHECK candidate for depth tracing — do NOT drop it as `UNVERIFIED`.

### 0d. Hardcoded Hazard Floor (TERTIARY FALLBACK — ledger-miss only, NOT the default)

This floor is a coarse last resort, not a substitute for 0a. Use it ONLY when
BOTH hold: (1) the authenticated projection has no researched row for the
dependency, AND (2) you have already emitted the matching
`NEEDS_DEPENDENCY_RESEARCH` escalation line for it per 0b. Do NOT reach for
this table as a first move, and do NOT treat a hit here as equivalent to an
authenticated researched row — it only lists
historical bug *classes* for a fixed list of famous protocols, not the
dependency's current real interface/semantics. Check EACH applicable
protocol against this minimum catalog:

This floor is keyed on the dependency's **TYPE** (generic mechanism), NOT on any
specific protocol name — brand-keyed rows are prohibited (a floor row naming a
specific protocol is the confirmed benchmark-contamination vector; see the HARD
no-overfit rule). Classify the detected dependency into a type below and check
the generic hazard class; use at most one illustrative brand only in prose, never
as the row key.

| Dependency Type | Generic Integration Hazard (class) | Check For |
|-----------------|-----------------------------------|-----------|
| AMM / swap pool | Slippage bypass when min-out may be 0; stale TWAP/observation read from an inactive pool; read-only reentrancy via pool-balance views during a callback | any swap call with zero/unbounded slippage; a price/observation read with no freshness assertion; a balance query during or after the external interaction |
| Lending / money market | First-depositor / empty-market exchange-rate rounding; flash-borrow-driven oracle shift within one tx; governance-mutable collateral factor assumed constant | receipt-token interaction at low total supply; an oracle read after interacting with the dependency; a hardcoded LTV / collateral factor |
| Oracle / price feed | Stale price (publisher or L2-sequencer downtime) consumed without a max-staleness check; confidence / exponent field ignored; feed or aggregator address assumed permanent | a price read with no freshness/staleness bound; use of the price without checking its confidence/exponent; a hardcoded feed address |
| Bridge / cross-chain messenger | Delivered value in a different FORM than the handler assumes (native vs wrapped auto-(un)wrap); message/return arity or ABI differing from the vendored interface; zero- or underfunded-gas send that "succeeds" without delivery | the inbound native↔wrapped conversion is present and the first value-moving op's form matches the delivered form; the real deployed message signature vs the vendored trait; the messenger's zero-gas success semantics |
| Staking / rebasing token | Balance changing between blocks with no transfer (rebase) used as an accounting input; share↔underlying conversion rate assumed constant | a `balanceOf` used as accounting that can rebase; a hardcoded or cached conversion rate |
| Delayed-claim / epoch ticket | State claimable only after an epoch/time boundary read as if immediately available | ticket/order state reads across an epoch or time boundary |
| Concentrated-liquidity / order-book DEX | Tick-density gas-exhaustion DoS on swap; permissionless cancellation of an order a third party can race | swap calls into narrow-tick pools; reading order/position state a third party can cancel or mutate |

**Note**: This floor lists generic hazard CLASSES by dependency type only — it is
minimum coverage, not exhaustive, and NOT a substitute for the live-researched
ledger (0a). Real research typically surfaces several more hazards specific to the
actual dependency.

### 0e. Embed Research Results in the Assigned Output

Write the hazard catalog as `## Integration Hazard Catalog` inside this
worker's one driver-assigned findings file. Do not create any other artifact.
Refer to the embedded catalog in Sections 1-4 so later phases receive it
through the authenticated assigned output.

---

## 1. Third-Party Race Conditions

For each YES/CHECK hazard in the catalog, ask:

**Permissionless function race**: Does the target protocol expose permissionless functions that modify state the audited code depends on? Can a third party call that function between the audited code's transactions?

| Target Function | Permissionless? | State Modified | Our Code Reads This State? | Race Window |
|----------------|----------------|----------------|---------------------------|-------------|
| {function} | YES/NO | {state var} | {where our code reads it} | {blocks/time} |

For each race with `Permissionless=YES` AND `Our Code Reads=YES`:
- Trace what happens if the third party acts first. Does our code read stale/zeroed state?
- Is the race atomic (same block) or cross-block?
- Can our code detect and recover, or is the damage permanent?

Tag: `[TRACE:third_party_call({target_function}) → our_read({our_function}) → state_is={stale/zeroed/modified} → impact={loss/revert/incorrect_accounting}]`

---

## 2. Integration State TOCTOU

For each external state the audited code reads:

| State Read | Read Location | Used At | Time Between Read and Use | Can State Change In Window? |
|-----------|---------------|---------|---------------------------|---------------------------|
| {value} | {our function:line} | {downstream use:line} | {same tx / cross-tx / cross-block} | YES/NO |

For each `Can Change=YES`:
- What changes it? (governance, permissionless function, oracle update, rebase, fee accrual)
- What is the worst-case delta in realistic conditions?
- Does the audited code have a freshness check or snapshot mechanism?

Tag: `[VARIATION:external_state({value}) fresh_at_read=X → stale_at_use=Y → delta={amount} → impact={consequence}]`

---

## Common False Positives

- **Hazard catalog hit with NO matching code path**: A known hazard exists for Protocol X, but the audited code never calls the affected function or reads the affected state. Do NOT report.
- **Permissionless function race with atomic protection**: If the audited code reads and uses external state within a single transaction AND verifies the result (e.g., slippage check, balance delta), the race window is zero. Do NOT report.
- **State TOCTOU with governance-only trigger**: If external state can only change via governance (timelock, multisig), and the audited code operates on a per-transaction timescale, the TOCTOU risk is informational at most.

**Coverage assertion**: Before returning, verify every entity enumerated under each section has been processed. Report enumerated vs analyzed counts in your return message.

## Step Execution Checklist (MANDATORY)

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 0a. Authenticated dependency projection consumed per target dependency | YES — exact bound input only | Y/N/? | |
| 0b. `NEEDS_DEPENDENCY_RESEARCH` emitted for every ledger-uncovered surface | YES for each uncovered surface | Y/N/? | |
| 0c. Hazard catalog compiled | YES | Y/N/? | |
| 0d. Floor catalog checked (TERTIARY — ledger-miss AND 0b escalation only) | IF 0a had no row AND 0b escalated | Y/N/? | |
| 0e. Hazard catalog embedded in the assigned findings output | YES — no second file | Y/N/? | |
| 1. Third-party race conditions | FOR EACH YES/CHECK hazard | Y/N/? | |
| 2. Integration state TOCTOU | FOR EACH external state read | Y/N/? | |
