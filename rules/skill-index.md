# Skill Index

> Skills are methodology files read by agents via `Read ~/.claude/agents/skills/{LANGUAGE}/{name}/SKILL.md`.
> The orchestrator resolves `{LANGUAGE}` to `evm`, `solana`, `aptos`, `sui`, `soroban`, or `daml` based on Step 0 detection.
> EVM has 18 skills, Solana has 20 skills, Aptos has 22 skills (21 + core directives), Sui has 22 skills (21 + core directives), Soroban has 19 skills, DAML has 12 skills - no shared skills directory exists.

## EVM Skills (`~/.claude/agents/skills/evm/`)

> Load these when `LANGUAGE=evm`. All 18 skills use EVM/Solidity concepts.

| Skill | Trigger Pattern | Used By |
|-------|-----------------|---------|
| FLASH_LOAN_INTERACTION | FLASH_LOAN or FLASH_LOAN_EXTERNAL flag | breadth agents, depth-token-flow, depth-edge-case |
| ORACLE_ANALYSIS | ORACLE flag | breadth agents, depth-external, depth-edge-case |
| TOKEN_FLOW_TRACING | BALANCE_DEPENDENT flag | depth-token-flow, breadth agents |
| ZERO_STATE_RETURN | ERC4626/first-depositor | depth-edge-case |
| STAKING_RECEIPT_TOKENS | Receipt token detected | breadth agents, depth-token-flow |
| EVENT_CORRECTNESS | >15 events detected (optional) | breadth agents |
| SEMI_TRUSTED_ROLES | SEMI_TRUSTED_ROLE flag | breadth agents, depth-state-trace |
| MIGRATION_ANALYSIS | MIGRATION flag | breadth agents |
| CROSS_CHAIN_TIMING | CROSS_CHAIN flag | depth-external |
| TEMPORAL_PARAMETER_STALENESS | TEMPORAL flag | breadth agents, depth-state-trace |
| CENTRALIZATION_RISK | 3+ privileged roles (optional) | breadth agents |
| SHARE_ALLOCATION_FAIRNESS | SHARE_ALLOCATION flag | breadth agents, depth-edge-case |
| FORK_ANCESTRY | Always (recon TASK 0) | recon agent |
| ECONOMIC_DESIGN_AUDIT | MONETARY_PARAMETER flag | breadth agents |
| EXTERNAL_PRECONDITION_AUDIT | External interactions | breadth agents |
| VERIFICATION_PROTOCOL | Always (verifiers) | security-verifier |
| STORAGE_LAYOUT_SAFETY | STORAGE_LAYOUT flag (proxy/upgradeable/diamond/delegatecall/sstore/sload/assembly) | depth-state-trace, depth-edge-case |
| CROSS_CHAIN_MESSAGE_INTEGRITY | CROSS_CHAIN_MSG flag (lzReceive/ccipReceive/receiveWormholeMessages/setPeer/setTrustedRemote) | breadth agents, depth-external |

## Solana Skills (`~/.claude/agents/skills/solana/`)

> Load these when `LANGUAGE=solana`. All 20 skills use Solana/Anchor concepts.

| Skill | Trigger Pattern | Used By |
|-------|-----------------|---------|
| ACCOUNT_VALIDATION | Always (Solana) | breadth agents, depth agents |
| CPI_SECURITY | CPI flag | breadth agents, depth agents |
| PDA_SECURITY | PDA flag | breadth agents, depth agents |
| ACCOUNT_LIFECYCLE | ACCOUNT_CLOSING flag | breadth agents, depth agents |
| TOKEN_2022_EXTENSIONS | TOKEN_2022 flag | breadth agents, depth agents |
| INSTRUCTION_INTROSPECTION | INSTRUCTION_INTROSPECTION flag | breadth agents, depth agents |
| SEMI_TRUSTED_ROLES | SEMI_TRUSTED_ROLE flag | breadth agents, depth-state-trace |
| MIGRATION_ANALYSIS | MIGRATION flag | breadth agents, depth-state-trace |
| CROSS_CHAIN_TIMING | CROSS_CHAIN flag | breadth agents, depth-external |
| TEMPORAL_PARAMETER_STALENESS | TEMPORAL flag | breadth agents, depth-state-trace |
| CENTRALIZATION_RISK | 3+ privileged roles (optional) | breadth agents, depth-state-trace |
| SHARE_ALLOCATION_FAIRNESS | SHARE_ALLOCATION flag | breadth agents, depth-edge-case |
| FORK_ANCESTRY | Always (recon TASK 0) | recon agent |
| ECONOMIC_DESIGN_AUDIT | MONETARY_PARAMETER flag | breadth agents |
| EXTERNAL_PRECONDITION_AUDIT | External interactions (CPI targets) | breadth agents |
| VERIFICATION_PROTOCOL | Always (verifiers) | security-verifier |
| TOKEN_FLOW_TRACING | BALANCE_DEPENDENT flag | depth-token-flow, breadth agents |
| ZERO_STATE_RETURN | Vault/first-depositor | depth-edge-case |
| FLASH_LOAN_INTERACTION | FLASH_LOAN flag | breadth agents, depth-token-flow, depth-edge-case |
| TRIDENT_API_REFERENCE | `trident_available: true` in build_status.md | invariant fuzz generator (Phase 4b), security-verifier Template 6 |

## Aptos Skills (`~/.claude/agents/skills/aptos/`)

> Load these when `LANGUAGE=aptos`. 21 standard skills + 1 core directive (22 total). All use Aptos Move concepts.

| Skill | Trigger Pattern | Used By |
|-------|-----------------|---------|
| MOVE_SAFETY_CORE_DIRECTIVES | Always (Aptos) — condensed inventory+flag directives from 4 always-required skills | breadth agents (loaded by orchestrator via commands/plamen.md) |
| ABILITY_ANALYSIS | Always (Aptos) | breadth agents, depth agents |
| BIT_SHIFT_SAFETY | Always (Aptos) | breadth agents, depth-edge-case |
| TYPE_SAFETY | Always (Aptos) | breadth agents, depth-state-trace |
| REF_LIFECYCLE | Always (Aptos) | breadth agents, depth-state-trace, depth-token-flow |
| FORK_ANCESTRY | Always (recon TASK 0) | recon agent |
| VERIFICATION_PROTOCOL | Always (verifiers) | security-verifier |
| ORACLE_ANALYSIS | ORACLE flag | breadth agents, depth-external, depth-edge-case |
| FLASH_LOAN_INTERACTION | FLASH_LOAN flag | breadth agents, depth-token-flow, depth-edge-case |
| TOKEN_FLOW_TRACING | BALANCE_DEPENDENT flag | depth-token-flow, breadth agents |
| ZERO_STATE_RETURN | Vault/first-depositor | depth-edge-case |
| SEMI_TRUSTED_ROLES | SEMI_TRUSTED_ROLE flag | breadth agents, depth-state-trace |
| TEMPORAL_PARAMETER_STALENESS | TEMPORAL flag | breadth agents, depth-state-trace |
| ECONOMIC_DESIGN_AUDIT | MONETARY_PARAMETER flag | breadth agents |
| EXTERNAL_PRECONDITION_AUDIT | External module interactions | breadth agents |
| MIGRATION_ANALYSIS | MIGRATION flag | breadth agents, depth-state-trace |
| CROSS_CHAIN_TIMING | CROSS_CHAIN flag | breadth agents, depth-external |
| FUNGIBLE_ASSET_SECURITY | FA_STANDARD flag | breadth agents, depth-token-flow |
| REENTRANCY_ANALYSIS | REENTRANCY flag | breadth agents, depth-state-trace |
| DEPENDENCY_AUDIT | EXTERNAL_LIB flag | breadth agents, depth-external |
| CENTRALIZATION_RISK | 3+ privileged roles (optional) | breadth agents |
| SHARE_ALLOCATION_FAIRNESS | SHARE_ALLOCATION flag | breadth agents, depth-edge-case |

## Sui Skills (`~/.claude/agents/skills/sui/`)

> Load these when `LANGUAGE=sui`. 21 standard skills + 1 core directive (22 total). All use Sui Move concepts.

| Skill | Trigger Pattern | Used By |
|-------|-----------------|---------|
| MOVE_SAFETY_CORE_DIRECTIVES | Always (Sui) — condensed inventory+flag directives from 4 always-required skills | breadth agents (loaded by orchestrator via commands/plamen.md) |
| ABILITY_ANALYSIS | Always (Sui) | breadth agents, depth agents |
| BIT_SHIFT_SAFETY | Always (Sui) | breadth agents, depth-edge-case |
| TYPE_SAFETY | Always (Sui) | breadth agents, depth-state-trace |
| OBJECT_OWNERSHIP | Always (Sui) | breadth agents, depth-state-trace, depth-token-flow |
| FORK_ANCESTRY | Always (recon TASK 0) | recon agent |
| VERIFICATION_PROTOCOL | Always (verifiers) | security-verifier |
| ORACLE_ANALYSIS | ORACLE flag | breadth agents, depth-external, depth-edge-case |
| FLASH_LOAN_INTERACTION | FLASH_LOAN flag | breadth agents, depth-token-flow, depth-edge-case |
| TOKEN_FLOW_TRACING | BALANCE_DEPENDENT flag | depth-token-flow, breadth agents |
| ZERO_STATE_RETURN | Vault/first-depositor | depth-edge-case |
| SEMI_TRUSTED_ROLES | SEMI_TRUSTED_ROLE flag | breadth agents, depth-state-trace |
| TEMPORAL_PARAMETER_STALENESS | TEMPORAL flag | breadth agents, depth-state-trace |
| ECONOMIC_DESIGN_AUDIT | MONETARY_PARAMETER flag | breadth agents |
| EXTERNAL_PRECONDITION_AUDIT | External package interactions | breadth agents |
| MIGRATION_ANALYSIS | MIGRATION flag | breadth agents, depth-state-trace |
| CROSS_CHAIN_TIMING | CROSS_CHAIN flag | breadth agents, depth-external |
| PTB_COMPOSABILITY | PTB flag | breadth agents, depth-external, depth-state-trace |
| PACKAGE_VERSION_SAFETY | PACKAGE_UPGRADE flag | breadth agents, depth-external |
| DEPENDENCY_AUDIT | EXTERNAL_LIB flag | breadth agents, depth-external |
| CENTRALIZATION_RISK | 3+ privileged roles (optional) | breadth agents, depth-state-trace |
| SHARE_ALLOCATION_FAIRNESS | SHARE_ALLOCATION flag | breadth agents, depth-edge-case |

## Soroban Skills (`~/.claude/agents/skills/soroban/`)

> Load these when `LANGUAGE=soroban`. 19 skills total (13 cross-language + 6 Soroban-specific). All use Soroban/Stellar Rust concepts.

| Skill | Trigger Pattern | Used By |
|-------|-----------------|---------|
| AUTH_VALIDATION | Always (Soroban) | breadth agents, depth agents |
| STORAGE_LIFECYCLE | Always (Soroban) | breadth agents, depth-state-trace, depth-edge-case |
| OVERFLOW_SAFETY | Always (Soroban) | breadth agents, depth-edge-case |
| CONTRACT_UPGRADEABILITY | `update_current_contract_wasm` detected | breadth agents, depth-state-trace |
| SEP41_TOKEN_SAFETY | SEP-41 token patterns detected | breadth agents, depth-token-flow, depth-edge-case |
| CUSTOM_TYPE_SAFETY | `contractimport!` or `contracttype` detected | breadth agents, depth-external |
| FORK_ANCESTRY | Always (recon TASK 0) | recon agent |
| VERIFICATION_PROTOCOL | Always (verifiers) | security-verifier |
| TOKEN_FLOW_TRACING | BALANCE_DEPENDENT flag | depth-token-flow, breadth agents |
| ZERO_STATE_RETURN | Vault/first-depositor | depth-edge-case |
| SEMI_TRUSTED_ROLES | SEMI_TRUSTED_ROLE flag | breadth agents, depth-state-trace |
| TEMPORAL_PARAMETER_STALENESS | TEMPORAL flag | breadth agents, depth-state-trace |
| ECONOMIC_DESIGN_AUDIT | MONETARY_PARAMETER flag | breadth agents |
| EXTERNAL_PRECONDITION_AUDIT | External contract interactions | breadth agents |
| FLASH_LOAN_INTERACTION | FLASH_LOAN flag | breadth agents, depth-token-flow, depth-edge-case |
| MIGRATION_ANALYSIS | MIGRATION flag (update_current_contract_wasm + storage migration) | breadth agents, depth-state-trace |
| CROSS_CHAIN_TIMING | CROSS_CHAIN flag | breadth agents, depth-external |
| CENTRALIZATION_RISK | 3+ privileged roles (optional) | breadth agents, depth-state-trace |
| SHARE_ALLOCATION_FAIRNESS | SHARE_ALLOCATION flag | breadth agents, depth-edge-case |

## DAML Skills (`~/.claude/agents/skills/daml/`)

> Load these when `LANGUAGE=daml`. 12 skills total (7 DAML-specific always-on + 5 cross-language carry-overs). All use DAML/Canton template-choice concepts.

| Skill | Trigger Pattern | Used By |
|-------|-----------------|---------|
| AUTHORIZATION_MODEL | Always (DAML) | breadth agents, depth-state-trace, depth-external |
| CHOICE_SEMANTICS | Always (DAML) | breadth agents, depth-state-trace, depth-edge-case |
| CONTRACT_KEY_SAFETY | Always (DAML) — self-skips if no `key`; `CONTRACT_KEY` flag | breadth agents, depth-state-trace |
| CID_CAPABILITY_SAFETY | Always (DAML) | breadth agents, depth-external, depth-edge-case |
| PRIVACY_DISCLOSURE | Always (DAML) | breadth agents, depth-edge-case |
| LOCKING_SEMANTICS | Always (DAML) — self-skips if no lock; `LOCKING` flag | breadth agents, depth-state-trace, depth-edge-case |
| ENSURE_INVARIANTS | Always (DAML) | breadth agents, depth-edge-case |
| VERIFICATION_PROTOCOL | Always (verifiers) | security-verifier |
| SEMI_TRUSTED_ROLES | SEMI_TRUSTED_ROLE flag | breadth agents, depth-state-trace |
| ECONOMIC_DESIGN_AUDIT | MONETARY_PARAMETER flag | breadth agents |
| SHARE_ALLOCATION_FAIRNESS | SHARE_ALLOCATION flag | breadth agents, depth-edge-case |
| TEMPORAL_PARAMETER_STALENESS | TEMPORAL flag | breadth agents, depth-state-trace |

> Carried niche agents for DAML appear in the `## Niche Agents` table below: `MULTI_STEP_OPERATION_SAFETY` (re-scoped to `PROPOSE_ACCEPT`) and `SPEC_COMPLIANCE_AUDIT` (`HAS_DOCS`, conformance-with-exploit only).
> Dropped by construction for DAML (no analog): FLASH_LOAN_INTERACTION, ORACLE_ANALYSIS / EXTERNAL_PRECONDITION_AUDIT (cross-template fetch-precondition lens absorbed into CID_CAPABILITY_SAFETY + CONTRACT_KEY_SAFETY), reentrancy, STORAGE_LAYOUT/proxy, TOKEN_2022/CPI/PDA/BIT_SHIFT/ABILITY/OBJECT_OWNERSHIP, MIGRATION_ANALYSIS/CROSS_CHAIN_*, CENTRALIZATION_RISK (single-controller-where-joint owned by AUTHORIZATION_MODEL). FORK_ANCESTRY reduced to a one-line recon note.

## Injectable Skills (`~/.claude/agents/skills/injectable/`)

> Injectable skills are protocol-type-specific. They load ONLY when recon classifies the protocol as the matching type.
> They are NOT counted in the per-tree standard skill set.
> They merge into existing agents via the standard merge hierarchy - they do NOT spawn new agents.

| Skill | Protocol Type Trigger | Inject Into |
|-------|----------------------|-------------|
| VAULT_ACCOUNTING | `vault` | Core state or economic design agent (M4) |
| ACCOUNT_ABSTRACTION_SECURITY | `account_abstraction` (ERC-4337, EntryPoint, UserOperation, Paymaster) | Breadth agents, depth-external |
| NFT_PROTOCOL_SECURITY | `nft` (ERC721/ERC1155 with marketplace, staking, or collateral logic) | Breadth agents, depth-token-flow, depth-edge-case |
| GOVERNANCE_ATTACK_VECTORS | `governance` (Governor, Timelock, voting, proposal, quorum, delegate) | Breadth agents, depth-external, depth-edge-case |
| OUTCOME_DETERMINISM | `outcome_determinism` (finite-pool selection with depletion fallback + time-gated actions with observable default/fallback outcomes). NOTE: callback selective revert and RNG consumption enumeration are now ALWAYS-ON in depth templates, not in this injectable. | Breadth agents, depth-edge-case |
| LENDING_PROTOCOL_SECURITY | `lending` (liquidate/borrow/repay/collateral/lend/loan/LTV/healthFactor/interestRate/debtToken) | Breadth agents, depth-token-flow, depth-edge-case, depth-state-trace |
| DEX_INTEGRATION_SECURITY | `dex_integration` (swap/addLiquidity/removeLiquidity/IUniswapV2Router/ISwapRouter/amountOutMin - AND protocol is NOT itself a DEX) | Breadth agents, depth-external, depth-edge-case |
| INTEGRATION_HAZARD_RESEARCH | `NAMED_EXTERNAL_PROTOCOL` (import/interface for identifiable external protocol — not standard libraries, not the protocol itself) | depth-external |
| CROSS_VM_SERIALIZATION_CONFORMANCE | `NON_EVM_TARGET` (EVM serializes for a non-EVM VM — Solana/Bitcoin/Move/Cosmos: pubkey/Borsh/base58/custom account-byte encoders). Outbound encoding conformance (CROSS_CHAIN_MESSAGE_INTEGRITY = inbound only). | Breadth cross-chain/encoding agent, depth-external |

### How Injectable Skills Work
1. Recon Agent classifies protocol type in TASK 0 Step 1
2. Recon Agent adds injectable skill recommendations to `template_recommendations.md` under `## Injectable Skills`
3. Orchestrator reads injectable recommendations during Phase 2 instantiation
4. Injectable skill methodology is APPENDED to the relevant agent's prompt (not a separate agent)
5. No new agents spawned - injectable skills increase depth of existing agents

## Niche Agents (`~/.claude/agents/skills/niche/`)

> Niche agents are flag-triggered STANDALONE agents. Unlike injectable skills (which append methodology to existing agents), niche agents spawn as independent agents in Phase 4b iteration 1. Each costs 1 depth budget slot.
> They are NOT counted in the per-tree standard skill set.
> Use niche agents instead of bloating scanner templates when a concern area needs focused depth.

| Niche Agent | Trigger Flag | Budget | Description |
|-------------|-------------|--------|-------------|
| EVENT_COMPLETENESS | `MISSING_EVENT` | 1 slot | Event emission coverage, parameter accuracy, cross-component event gaps |
| SEMANTIC_GAP_INVESTIGATOR | `sync_gaps >= 1` OR `accumulation_exposures >= 1` OR `conditional_writes >= 1` OR `cluster_gaps >= 1` (from Phase 4a.5) | 1 slot | Investigates SYNC_GAP, ACCUMULATION_EXPOSURE, CONDITIONAL, and CLUSTER_GAP flags from semantic invariants to conclusion |
| SPEC_COMPLIANCE_AUDIT | `HAS_DOCS` flag (non-empty DOCS_PATH with testable claims). **DAML**: `HAS_DOCS` — emit a finding ONLY when a doc mismatch is exploitable; demote pure doc mismatch to Informational. | 1 slot | Spec-to-code compliance: extracts doc claims, verifies against code, reports mismatches |
| SIGNATURE_VERIFICATION_AUDIT | `HAS_SIGNATURES` flag (ecrecover/ECDSA.recover/permit/EIP712/domainSeparator/nonces/isValidSignature) | 1 slot | Signature replay, malleability, EIP-712 domain, permit front-run, nonce management, cross-chain replay |
| SEMANTIC_CONSISTENCY_AUDIT | `HAS_MULTI_CONTRACT` flag (2+ in-scope contracts sharing parameters or formulas) | 1 slot | Config variable unit mismatches, formula semantic drift, magic number consistency across contracts |
| MULTI_STEP_OPERATION_SAFETY | `MULTI_STEP_OPS` flag (approve/delegate/authorize patterns + on-behalf-of functions: depositFor/stakeFor/delegateTo/mintFor/withdrawFor). **DAML**: re-scoped to `PROPOSE_ACCEPT` — propose template + accept choice; flag accept re-reading mutable state the proposer signed against, propose acceptable under different terms, non-revocable propose. | 1 slot | Authorization sequence conflicts in batch/multi-step operations, infrastructure address targeting via public on-behalf-of functions |
| CALLBACK_RECEIVER_SAFETY | `OUTCOME_CALLBACK` flag (onERC721Received/onERC1155Received/tokensReceived/onTransferReceived/onFlashLoan/executeOperation/receive()/fallback()) | 1 slot | (EVM only) Callback handler access control, permissionless state inflation via callbacks, selective revert exploitation |
| DIMENSIONAL_ANALYSIS | `MIXED_DECIMALS` flag (mulDiv/mulWad/rayMul or mul_div/mul_div_floor/mul_div_wide + 1e6/1e8/10^N/decimals()/10** in scope) | 1 slot | (All languages) Unit/scale mismatch detection: vocabulary discovery, expression annotation, cross-function propagation, boundary substitution. Sequential 4-phase methodology requires single agent context. |
| STABLESWAP_COMPLIANCE | `STABLESWAP_FORK` flag (fork-ancestry detects Curve/StableSwap parent via get_d/get_y/ramp_a patterns) | 1 slot | Curve spec compliance: Newton-Raphson convergence, A parameter encoding (A vs A*N^(N-1)), reserve decimal normalization, fee consistency, known Curve vulnerability patterns. All languages. |

### How Niche Agents Work
1. Recon Agent 3 detects trigger flag (e.g., `MISSING_EVENT` from setter_list.md/emit_list.md)
2. Recon adds niche agent to `template_recommendations.md` → `## Niche Agents` in BINDING MANIFEST
3. Orchestrator reads niche agent definition from `~/.claude/agents/skills/niche/{name}/SKILL.md`
4. Orchestrator spawns niche agent in Phase 4b iteration 1 alongside standard depth agents
5. Niche agent writes to `{SCRATCHPAD}/niche_{name}_findings.md`
6. Chain analysis reads niche agent output alongside depth/scanner findings

### When to Use Niche Agents vs Injectable Skills vs Scanner Sub-Checks
| Criteria | Scanner Sub-Check | Injectable Skill | Niche Agent |
|----------|------------------|-----------------|-------------|
| Lines of methodology | ≤5 | 10-100 | 50-150 |
| Applies universally? | Yes | No (protocol-type) | No (flag-triggered) |
| Spawns new agent? | No | No | **Yes** (1 budget slot) |
| Depth of analysis | Surface scan | Medium (enriches existing agent) | **Deep** (entire agent focused on one concern) |
| Use when | Quick check, low FP risk | Protocol-type-specific methodology | Concern needs dedicated focus, scanner sub-check is insufficient |

## L1 Skills (`~/.claude/agents/skills/injectable/l1/`)

> **Status**: Experimental — loaded only when `/plamen l1` mode is invoked.
> **Trigger detection**: Recon agent sets `L1_PATTERN=true` when it detects an L1 / node-client codebase (Go or Rust) via imports such as `reth-*`, `libp2p`, `cometbft`, `cosmos-sdk`, `beacon-chain/`, `eth/protocols`, `fork_choice`, `x/staking`. Subsystem flags (CONSENSUS, P2P, MEMPOOL, LIGHT_CLIENT, RPC, BLS, STATE_SYNC, EXECUTION, XENV, VALIDATOR_LIFECYCLE, HARDFORK) are set per detected module.
> **Injection**: Skills are APPENDED to `depth-consensus-invariant` or `depth-network-surface` (new agent roles defined in `~/.claude/agents/depth-consensus-invariant.md` and `~/.claude/agents/depth-network-surface.md`). They do NOT spawn new agents per the Plamen injectable-skill convention.
> **Severity**: All L1 findings use the matrix in `docs/l1-mode/severity-matrix.md`, not the smart-contract matrix in `rules/report-template.md`.

| Skill | Trigger Pattern | Inject Into |
|-------|-----------------|-------------|
| CONSENSUS_SAFETY_INVARIANTS | `CONSENSUS` flag (always on for L1) | depth-consensus-invariant |
| CONSENSUS_MATH_CORRECTNESS | `CONSENSUS` flag + `adjust_difficulty` / `difficulty_adjust` / `ema` / `moving_average` / `reward_curve` / `target_time` detected | depth-consensus-invariant, depth-edge-case |
| FORK_CHOICE_AUDIT | `CONSENSUS` + `fork_choice/` / `ghost/` / `lmd/` / `choice.rs` detected | depth-consensus-invariant |
| P2P_DOS_AND_ECLIPSE | `P2P` flag (`p2p/`, `network/`, `discovery/`, `libp2p`, `devp2p`, `discv5`) | depth-network-surface |
| MEMPOOL_ASYMMETRIC_DOS | `MEMPOOL` flag (`txpool/`, `mempool/`, `blob_pool`) | depth-network-surface, depth-state-trace |
| LIGHT_CLIENT_PROOF_VERIFICATION | `LIGHT_CLIENT` flag (`light_client/`, `ics23/`, `merkle/`, `ibc/`) | depth-consensus-invariant, depth-external |
| RPC_SURFACE_AUDIT | `RPC` flag (`rpc/`, `jsonrpc`, `engine_api`, `eth/api`) | depth-network-surface |
| BLS_AGGREGATION_AUDIT | `BLS` flag (`bls/`, `blst`, `milagro`, `pairing`, `proof_of_possession`) | depth-consensus-invariant, depth-external |
| STATE_SYNC_PRUNING | `STATE_SYNC` flag (`sync/`, `snap_sync`, `statesync`, `pruning`, `snapshot/`) | depth-state-trace, depth-edge-case |
| EXECUTION_CLIENT_HARDENING | `EXECUTION` flag (`core/vm/`, `revm`, `interpreter`, `svm/`, `move-vm`) | depth-state-trace, depth-consensus-invariant |
| CROSS_ENVIRONMENT_SEMANTIC_DRIFT | `XENV` flag (fork of EVM client OR L2 rollup OR EVM-on-non-EVM OR precompile wrapping native host) | depth-external, depth-state-trace |
| VALIDATOR_LIFECYCLE_AND_SLASHING | `VALIDATOR_LIFECYCLE` flag (`x/staking`, `x/slashing`, `validator/`, `unbonding`) | depth-state-trace, depth-consensus-invariant |
| HARDFORK_ACTIVATION_AND_PROTOCOL_UPGRADE | `HARDFORK` flag (`fork_rules`, `chain_config`, `x/upgrade`, `ActivationHeight`) | depth-state-trace, depth-consensus-invariant |
| GO_CONCURRENCY_SAFETY | Always on for L1 + `LANGUAGE=go` | every L1 agent on Go code |
| RUST_UNSAFE_AUDIT | Always on for L1 + `LANGUAGE=rust` | every L1 agent on Rust code |
| DEPENDENCY_AUDIT_NODECLIENT | Always on for L1 (extends existing dependency-audit skill) | recon agent + every breadth agent |
| DATA_AVAILABILITY_ENFORCEMENT | Protocol-type trigger: `data_availability` / `storage` / `da_chain` / `blob_storage` (Arweave/Celestia class) | depth-consensus-invariant, depth-state-trace |
| PEER_SCORING_CORRECTNESS | `P2P` flag + `score_peer` / `peer_score` / `reputation` / `ban_peer` detected | depth-network-surface |
| GOSSIP_CACHE_INVARIANCE | `P2P` flag + `seen_cache` / `message_cache` / `tx_cache` / `gossipsub` detected | depth-network-surface, depth-consensus-invariant |
| CONSENSUS_TX_IDENTITY_INVARIANTS | `CONSENSUS` flag + `txid` / `tx_hash` / `nonce` / `sequence` / `signature` across modules | depth-consensus-invariant, depth-state-trace |
| CONFIG_CORRECTNESS | `L1_PATTERN` + `config/` / `settings` / constants / docs or comments with protocol bounds | depth-edge-case, depth-state-trace |
| WRITE_ERROR_DIVERGENCE | `STORAGE` or `DATABASE_TX` flag + file/DB write APIs (`write_all`, `fs::write`, `rename`, `commit`, `batch`, `transaction`) | depth-state-trace, depth-edge-case |
| COSMOS_SDK_MODULE_SAFETY | COSMOS_SDK flag (cosmos-sdk/cometbft/tendermint/x/ modules) | depth-consensus-invariant, depth-state-trace |
| COSMOS_IBC_SECURITY | IBC flag (ibc-go/ics23/IBC channels) | depth-consensus-invariant, depth-external |

### L1 depth agent roles (new in L1 mode)

Two new depth agents are added for L1 mode, living alongside the existing `depth-token-flow`, `depth-state-trace`, `depth-edge-case`, `depth-external`:

- **`depth-consensus-invariant`** — consensus safety/liveness invariants, non-determinism sweeps, Byzantine-scenario reasoning, cross-client differential. Definition: `~/.claude/agents/depth-consensus-invariant.md`.
- **`depth-network-surface`** — p2p/RPC/mempool attack surface enumeration, pre-auth panic sweeps, asymmetric cost analysis, eclipse-vector check, rate-limit audit. Definition: `~/.claude/agents/depth-network-surface.md`.

Existing depth agents that remain useful in L1 mode: `depth-state-trace` (storage/pruning), `depth-external` (dependency audits, cross-client), `depth-edge-case` (boundary conditions). `depth-token-flow` does NOT load in L1 mode (no in-scope DeFi token flow).

### L1 pipeline differences

- **Phase 4c (chain analysis) is REMOVED** for L1 mode. L1 bugs are point vulnerabilities; enabler enumeration and postcondition→precondition matching do not apply. See `docs/l1-mode/design.md` Section 4.
- **Phase 5 verification** uses new evidence tags: `[DIFF-PASS]`, `[CONFORMANCE-PASS]`, `[NON-DET-PASS]`, `[FUZZ-PASS]`, `[LSP-TRACE]` alongside the existing `[CODE-TRACE]`. See `prompts/l1/phase5-verification-prompt.md`.
- **Phase 0.5 Bake** runs `scip-go` / `rust-analyzer scip` / `opengrep` once per audit. See `docs/l1-mode/design.md` Section 5.2.
