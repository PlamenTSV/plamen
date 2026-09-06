# Plamen Claude–Codex Backend Semantic Parity

## Implementation Blueprint

**Date:** 2026-07-24  
**Scope:** smart-contract and L1 Plamen pipelines  
**Status:** implementation-ready design; no implementation or validation was performed as part of this blueprint  
**Repository reviewed:** `<LOCAL_USER_ROOT>\plamen-codex-implementation`  
**Normative goal:** preserve the current Claude behavior as the legacy regression baseline while making Codex a fair, explicitly measured challenger under the same semantic work, capability, and resource contract

---

## 1. Executive decision

Plamen must stop treating a backend as both the author of audit work and the transport used to execute it. The driver must author one immutable semantic plan before either backend is selected:

```text
source snapshot + audit policy + deterministic facts
                     |
                     v
            SemanticWorkPlan roster
                     |
                     v
          SemanticPromptSnapshot bytes
                     |
          +----------+----------+
          |                     |
          v                     v
  Claude transport plan   Codex transport plan
          |                     |
          +----------+----------+
                     v
             WorkerTransaction
                     |
                     v
        PhaseIO incorporation and commit
```

Claude and Codex may differ only in transport mechanics: executable, argument encoding, session framing, stream decoding, and provider-specific telemetry parsing. They may not differ in worker roster, semantic prompt, methodology selection, output assignment, tool capabilities, retry budget, context/output/tool ceilings, phase gates, or validator thresholds.

The cutover must use two explicit compatibility profiles:

1. `legacy_claude_v1`
   - This is the regression baseline.
   - An absent `semantic_plan_version` in an existing configuration resolves to this profile.
   - Existing Claude PTY/headless prompt construction, phase promotion, argv, artifact handling, and checkpoint behavior remain reachable without semantic reinterpretation.
   - It is not modified merely to make Codex look similar.
   - Additive supervisor receipts are permitted only outside model-visible and source-snapshot namespaces, and only after byte-for-byte legacy regression proves they do not change behavior.

2. `semantic_v1`
   - This is the backend-neutral production target and the only profile eligible for Claude-versus-Codex parity claims.
   - Every model or native worker is a driver-owned `SemanticWorkPlan` unit executed through `WorkerTransaction`.
   - Nested model-owned audit agents are forbidden.
   - Missing capabilities fail closed into explicit debt. They never cause extra workers, hidden fallbacks, weaker validators, or unrecorded model substitution.

`semantic_v1` must not become the default until the P0-AM worker-lifecycle cutover and P0-AE PhaseIO/commit authority are live on every production launch path. A prompt-only parity patch would preserve the most important existing defects: unowned descendants, direct canonical writes, backend-specific fanout, and silent model/tool fallbacks.

The terminal legacy Claude audit that stopped at 70/75 remains a regression artifact only. It must not be resumed, scored, or used as a proof of backend parity.

<PRIVATE_AUDIT_TARGET> and <PRIVATE_REGRESSION_TARGET> are explicitly outside this blueprint’s execution scope. They remain user-run post-handoff audits. No <PRIVATE_AUDIT_TARGET> or <PRIVATE_REGRESSION_TARGET> audit, test, ground-truth evaluation, or configuration was run or changed during this work.

---

## 2. Normative acceptance boundary

Backend parity means all of the following, not merely “both backends can finish”:

- The same ordered semantic roster exists before launch.
- Every paired worker has the same semantic role, inputs, methodology bytes, obligations, expected outputs, and completion rule.
- The canonical semantic prompt bytes are identical.
- Backend-specific launch overlays contain transport instructions only and cannot add analysis, output, tool, or child-agent obligations.
- Model selection is by an explicit capability tier and exact model receipt, not by a provider-name analogy.
- The same context, output, tool-call, retry, and native-execution grants apply.
- Tool restrictions are enforceable and produce receipts; prompt prose is not authority.
- Every child process is owned, joined, and proven closed before output parsing or PhaseIO incorporation.
- Every output is staged per attempt and published by compare-and-swap after completion.
- Backend/model fallback creates a new plan generation or explicit debt.
- The same phase gates and artifact thresholds apply.
- Resume never erases, reinterprets, or silently adopts a different backend’s unfinished work.
- A parity receipt can replay the above claims from immutable bytes.

The following do **not** establish parity:

- both backends receiving a prompt with similar prose;
- equal top-level phase counts while one backend nests unmeasured agents;
- equal model labels such as “opus” and “GPT” without capability receipts;
- equal configured budgets when one backend receives a timeout multiplier or extra retries;
- successful artifacts written directly to canonical paths;
- a weaker Codex validator allowing output that Claude must repair;
- Codex falling back to the account-default model;
- an MCP phase silently using web search on only one backend;
- an end-to-end score without structural parity receipts.

---

## 3. Evidence and prerequisite ledger

This design is grounded in the current repository and the following controlling documents:

- `Plamen_Goal_Acceptance_Ledger_2026-07-17.md`
- `Plamen_Plan_Completion_Audit_2026-07-24.md`
- `Plamen_P0-AM_Worker_Lifecycle_Forensic_2026-07-24.md`
- `Plamen_WorkerTransaction_P0-AM_Implementation_Design_2026-07-24.md`
- `Plamen_Adaptive_Attention_Implementation_Blueprint_2026-07-24.md`
- `Plamen_Typed_CPG_Implementation_Blueprint_2026-07-24.md`
- `Plamen_Mechanical_Gate_Registry_Implementation_Blueprint_2026-07-24.md`
- `docs/terminal-legacy-claude-audits.md`
- `docs/codex-backend.md`
- current driver, prompt compiler, phase model, PTY, Codex adapter, PhaseIO, worker receipt, wizard, and test sources

The acceptance ledger controls the order:

1. Finish PhaseIO compare-and-swap and phase commit authority.
2. Finish P0-AM production worker ownership, descendant closure, and late-write prevention.
3. Preserve non-destructive startup/resume.
4. Preserve finding identity, security obligations, candidate negatives, and independent-negative evidence.
5. Add backend parity on top of those authorities.
6. Validate with synthetic and non-ground-truth canaries.
7. Hand off <PRIVATE_AUDIT_TARGET> and <PRIVATE_REGRESSION_TARGET> to the user.

The typed CPG and adaptive-attention designs are not optional side projects for parity. They define two backend-neutral inputs that must remain outside transport:

- Typed program facts are model-free provider artifacts. A Claude or Codex adapter must receive the same validated slice; neither may regenerate or reinterpret the graph.
- Adaptive attention is an obligation-to-evidence-channel compiler. Its roster and resource grants must be frozen before backend transport and must not depend on provider-specific raw finding counts.

---

## 4. Current phase registry: complete inventory

The declared registry contains 75 smart-contract phases and 59 L1 phases. “Declared model” below is the `Phase` registry tier before runtime promotion, Light-mode forcing, Codex alias mapping, or fallback.

### 4.1 Smart-contract phases

| Family | Phases | Modes | Declared model / special capability |
|---|---|---|---|
| Recon and instantiation | `recon`, `instantiate`, `breadth` | all | Sonnet |
| Thorough rescan | `rescan_prepare`, `rescan` | Thorough | Haiku planner, Sonnet workers |
| Inventory | `inventory_prepare`, `inventory_chunk_a`, `inventory_chunk_b`, `inventory_chunk_c`, `inventory` | all | Haiku planner, Sonnet chunks/merge |
| Semantic invariants | `invariants`, `invariants_p2` | Core/Thorough; pass 2 Thorough | Sonnet |
| Depth and repair | `depth`, `attention_repair`, `exploration_skeptic`, `enumgap_exploration`, `application_skeptic`, `axis_coverage` | depth all; others mode-gated | Opus depth; Sonnet repair/skeptic |
| Dedup and precedent | `sc_semantic_dedup`, `rag_sweep` | dedup all; RAG Core/Thorough | Sonnet; `rag_sweep` declares MCP |
| Chain | `chain`, `chain_agent2`, `chain_iter2` | first two all; iter 2 Thorough | Sonnet declared |
| Verify planning | `sc_verify_queue` | all | Haiku |
| Critical/high verification | `sc_verify_crithigh`, `sc_verify_high_b`, `sc_verify_high_c`, `sc_verify_high_d`, `sc_verify_high_e`, `sc_verify_high_f`, `sc_verify_high_g`, `sc_verify_high_h`, `sc_verify_high_i`, `sc_verify_high_j` | all | Sonnet declared |
| Medium verification | `sc_verify_medium_a`, `sc_verify_medium_b`, `sc_verify_medium_c`, `sc_verify_medium_d`, `sc_verify_medium_e`, `sc_verify_medium_f`, `sc_verify_medium_g`, `sc_verify_medium_h`, `sc_verify_medium_i`, `sc_verify_medium_j` | all | Sonnet declared |
| Low verification | `sc_verify_low_a`, `sc_verify_low_b`, `sc_verify_low_c`, `sc_verify_low_d`, `sc_verify_low_e`, `sc_verify_low_f`, `sc_verify_low_g`, `sc_verify_low_h`, `sc_verify_low_i`, `sc_verify_low_j` | Thorough | Sonnet |
| Verify aggregation and post-processing | `sc_verify_aggregate`, `sc_mechanical_verify`, `post_verify_extract`, `skeptic`, `crossbatch`, `severity_adjudication_shadow` | mixed | Haiku aggregate; Sonnet; Opus adjudication shadow |
| Report planning and model bodies | `report_index`, `report_body_writer_critical_high`, `report_body_writer_medium`, `report_body_writer_low_info` | all | Sonnet declared |
| Report tier projection/merge | `report_critical_high`, `report_critical_high_merge`, `report_medium`, `report_medium_merge`, `report_low_info`, `report_low_info_merge` | all | Haiku |
| Report assembly and gates | `report_assemble`, `report_dedup_agent`, `report_dedup`, `report_disposition`, `report_floor` | all | Sonnet |

The declared timeouts range from 60 seconds for driver-like planners to 10,800 seconds for breadth. The current runtime then applies LOC/hypothesis scaling and a Codex-only multiplier.

### 4.2 L1 phases

| Family | Phases | Modes | Declared model / special capability |
|---|---|---|---|
| Bake and recon | `bake`, `recon`, `breadth`, `graph_sweeps` | first three all; graph Thorough | Sonnet bake/breadth/graph; Opus recon |
| Inventory | `inventory_prepare`, `inventory_chunk_a`, `inventory_chunk_b`, `inventory_chunk_c`, `inventory` | all | Haiku planner, Sonnet chunks/merge |
| Recovery and invariants | `location_recovery`, `invariants`, `invariants_p2` | mode-gated | Sonnet |
| Depth and repair | `depth`, `attention_repair`, `enumgap_exploration`, `application_skeptic` | depth all; others mode-gated | Opus depth; Sonnet repair |
| Verify planning and discovery normalization | `verify_queue`, `semantic_dedup`, `rag_sweep` | queue/dedup all; RAG Core/Thorough | Haiku queue; Sonnet; RAG declares MCP |
| Critical/high verification | `verify_crithigh`, `verify_high_b`, `verify_high_c`, `verify_high_d`, `verify_high_e`, `verify_high_f`, `verify_high_g`, `verify_high_h`, `verify_high_i`, `verify_high_j` | all | Sonnet declared |
| Medium verification | `verify_medium_a`, `verify_medium_b`, `verify_medium_c`, `verify_medium_d`, `verify_medium_e`, `verify_medium_f` | all | Sonnet |
| Low verification | `verify_low_a`, `verify_low_b`, `verify_low_c`, `verify_low_d` | Thorough | Sonnet |
| Verify aggregation and post-processing | `verify_aggregate`, `mechanical_verify`, `post_verify_extract`, `skeptic`, `crossbatch`, `severity_adjudication_shadow` | mixed | Haiku aggregate; Sonnet; Opus adjudication shadow |
| Report planning and model bodies | `report_index`, `report_body_writer_critical_high`, `report_body_writer_medium`, `report_body_writer_low_info` | all | Sonnet declared |
| Report tier projection/merge | `report_critical_high`, `report_critical_high_merge`, `report_medium`, `report_medium_merge`, `report_low_info`, `report_low_info_merge` | all | Haiku |
| Report assembly and gates | `report_assemble`, `report_dedup`, `report_disposition`, `report_floor` | all | Sonnet |

The generated Codex `AGENTS.md` says Codex skips L1 Bake and produces its index during recon, while the live phase registry still contains `bake` and the driver contains bake/recon graph-preparation logic. This is documentation/runtime drift. The implementation must derive capability and provider inventories from executable registries, not copy this claim into the semantic plan.

### 4.3 Runtime model divergence across the registry

The declared phase model is not the effective model:

- Light forces the Claude path to Sonnet.
- Claude Thorough applies promotions after the Codex branch in `phase_model`.
- Current Thorough promotions include reasoning-heavy discovery, verification, chain/consolidation, and report paths.
- The Codex branch returns before those promotions, so the same phase may receive a lower semantic tier solely because the backend is Codex.
- A current regression test explicitly preserves “Codex paths unchanged,” which proves this is intentional legacy behavior, not parity.
- Codex maps `opus`, `sonnet`, and `haiku` to provider model IDs, but unknown aliases silently resolve to the Sonnet mapping.
- Codex can silently replace an unavailable model through runtime fallback fields, or retry without `--model` after ChatGPT-auth rejection.

`semantic_v1` must resolve the semantic capability tier before backend mapping. Backend mapping is then exact and fail-closed.

---

## 5. Current worker and provider path inventory

### 5.1 Model worker launch paths

| Path | Current provider/transport | Current semantic shape | Principal parity issue |
|---|---|---|---|
| `run_phase` → `ClaudePtySession.spawn` | Claude PTY | persistent session, completion marker/quiescence, phase-dependent child permissions | PTY completion is provisional until process-tree closure; prompt contract is Claude-specific |
| `run_phase` → `subprocess.Popen` | Claude headless | one `claude -p` process | direct canonical writes; no universal WorkerTransaction |
| `run_phase` → `_run_one_codex_exec` | Codex exec | one `codex exec` process | Codex-translated prompt, dangerous sandbox bypass, pre-created outputs, silent model fallbacks |
| `_run_single_recon_worker_pty` / `_run_recon_worker_pool_pty` | Claude PTY pool | driver-owned recon leaves, fixed 2/4 roster, concurrency up to 4 | not mirrored by a driver-owned Codex roster |
| generic Codex recon prompt | Codex nested agents | parent asks Codex to spawn and wait for children | children inherit parent model/sandbox, lack WorkPlans and exact receipts |
| `_run_single_breadth_worker_pty` / breadth pool | Claude PTY pool | manifest rows, concurrent workers | Codex/headless execute same rows serially |
| `_run_breadth_backend_fanout` | Codex exec or Claude headless | Python-rendered canonical row prompts, serial | good prompt-row substrate; still direct writes and transport-specific budgets |
| `_run_single_rescan_worker_pty` / rescan pool | Claude PTY pool | driver-owned rows | Codex uses coordinator/nested-agent semantics |
| `_run_single_depth_worker_pty` / `_run_depth_worker_batch` | Claude PTY pool | fixed and flag-triggered roles, concurrent | role/model/runtime differs from Codex |
| `_run_depth_codex_fanout` | Codex exec | canonical depth jobs, serial, per-job retry | all jobs inherit one phase model; direct writes; no WorkerTransaction |
| `_execute_dynamic_verifier_launch` | Claude PTY or headless/Codex argv | bounded verifier work unit | foreground join is improved, but not integrated with the universal transaction authority |
| `_run_dynamic_verifier_unit` / recovery callers | mixed | verifier roster/recovery units | must use the same semantic generation and attempt rules as all other workers |
| `_run_isolated_chain_tail_model_attempt` | isolated model path | bounded chain-tail shard | a useful PhaseIO precedent; must converge on the shared plan/transaction API |
| `_respawn_missing_only` and resume helpers | Claude PTY | continuation/missing-only session | retry identity and generation must be made universal |
| retired `_run_verify_recovery_shard_legacy_retired` | raw subprocess | legacy recovery | must remain unreachable or be deleted after migration proof |

The generated Codex adapter contains role TOMLs for recon, breadth, four depth roles, scanner, inventory, chain, verifier, rescan, per-contract, semantic invariant, scoring, RAG, niche, and report roles. Those files do not govern production driver workers: live `codex exec` is launched with `--ignore-user-config` and `--ignore-rules`. The generated role model choices and MCP settings therefore cannot be cited as runtime parity evidence.

### 5.2 Native and mechanical providers

Native execution is also part of backend fairness because a model may request or consume its results:

| Provider area | Current process authority | Required target |
|---|---|---|
| `worker_execution_receipts.run_observed_worker` | provider-owned Popen, bounded streams, output staging, process-tree receipt | become the universal execution substrate or be wrapped by `WorkerTransaction` |
| `fuzz_workspace_authority` | separate Windows Job/Popen authority | use the same owned-process primitive; do not maintain a competing lifecycle |
| `recon_prepass._run_hardened` | raw Popen plus hardened tree kill | `NativeCommandAdapter` WorkPlan |
| `mechanical_verify` | multiple `subprocess.run` test/build calls | bounded native child WorkPlans with exact command/toolchain receipts |
| `audit_snapshot` git/version probes | `subprocess.run` | deterministic provider receipts; reusable across backends when bytes match |
| `supply_chain_gate` | offline scanner subprocess | native provider capability and toolchain digest |
| `spike_mechanical_poc` | Forge subprocess | native test WorkPlan |
| `plamen_display` diagnosis | diagnostic Popen/kill | supervisor-only process scope, never semantic audit evidence |
| `preflight_pty_transports` | version probe | supervisor-only transport capability receipt |
| PTY implementation | `winpty.PtyProcess.spawn` or POSIX Popen/session group | transport adapter owned by WorkerTransaction |

Typed CPG providers must join this native-provider registry:

- EVM: pinned Slither helper
- Go: pinned SSA provider
- Rust: pinned SCIP/rust-analyzer provider
- Solana and Soroban: explicit host adapters
- Aptos and Sui: separate Move providers
- DAML: unsupported until a pinned provider exists

Their fact snapshots are model-free, backend-neutral PhaseIO inputs. MCP output is not a typed graph fact authority.

### 5.3 Current prompt compilation paths

The current prompt is backend-aware before launch:

- `build_phase_prompt` chooses different execution-contract prose for Claude PTY, Claude headless, and Codex.
- Claude direct/coordinator classifications differ from Codex’s `CODEX_MULTI_AGENT_PHASES`.
- `_translate_prompt_for_codex` rewrites paths, Claude/Task terminology, child-agent instructions, depth checklists, and output handling.
- The common header can still describe `claude -p` even when the target is Codex.
- Legacy methodology paths beginning `~/.claude/` are normalized by runtime placeholder rendering to canonical Plamen home, then Codex receives another translation layer.
- Codex requires `~/.codex/plamen` to exist even though prompt compilation already has a canonical methodology root.

There is useful substrate: breadth and depth row plans already have tests demonstrating identical canonical row prompts and methodology digests for serial Claude-headless and Codex launchers. That row-level work must become the universal compiler, not remain a special-case fanout.

---

## 6. Current Claude–Codex divergence ledger

| ID | Dimension | Claude legacy | Codex current | Semantic risk | Required disposition |
|---|---|---|---|---|---|
| D-01 | Fanout | driver-owned PTY pools for recon/breadth/rescan/depth | nested agents for some phases; serial row fanout for others | different worker denominator and attention allocation | driver compiles and launches the same leaf roster |
| D-02 | Nested agents | Claude leaf tool denial exists on many paths | Codex prompt may call `spawn_agent`; children inherit parent capabilities | children are not PhaseIO/WorkerTransaction units | forbid nested audit agents in `semantic_v1` |
| D-03 | Prompt | PTY/headless-specific execution prose | broad Codex translation mutates analysis and output instructions | no common semantic bytes | split semantic snapshot from transport overlay |
| D-04 | Model tiers | Thorough promotions occur | Codex returns before promotions | unequal reasoning allocation | resolve capability tier before provider mapping |
| D-05 | Model fallback | Claude aliases/environment overrides | Codex capacity chain, unavailable-model map, or no-model retry | provider/model can change in place | exact model or new generation/debt |
| D-06 | Reasoning control | model-native behavior, no common receipt | `model_reasoning_effort=high` only for selected o-series models | nominal model equality hides reasoning difference | capability registry binds reasoning mode and support |
| D-07 | MCP | phase-based Claude allow/deny; installed MCP may be available | live driver ignores user config, so generated MCP config is not loaded | RAG capability is absent or replaced | strict intersection profile or driver-brokered provider |
| D-08 | Web/network | Claude disallows WebSearch/WebFetch except selected phases | Codex dangerous bypass leaves network available; prose asks for web fallback | tool policy is unenforceable and asymmetric | OS/broker enforcement plus exact receipts |
| D-09 | Filesystem tools | Claude exact consumer hook exists only on limited phases | no equivalent hook; broad project/scratchpad add-dirs | unregistered reads/writes | universal backend-neutral tool manifest and attempt view |
| D-10 | Sandbox | Claude uses dangerous permission bypass plus deny lists/hooks | Codex uses `--dangerously-bypass-approvals-and-sandbox` | both rely too much on prompt/CLI behavior | constrained attempt view and fail-closed capability preflight |
| D-11 | Transport | persistent PTY or headless | one-shot JSONL exec | session/compaction/completion differs | adapters expose only transport observations |
| D-12 | Timeout | base/LOC/hypothesis scaling | same basis plus 3× multiplier, up to six hours | unequal resource grant | equal semantic timeout in parity mode |
| D-13 | Retry | phase-level and pool-specific rules | additional model/capacity/no-model branches | unequal total budget and identity drift | immutable attempt policy in WorkPlan |
| D-14 | Output pre-state | model generally creates/writes files | expected files are pre-created for apply-patch behavior | empty canonical files can satisfy weak gates | identical attempt-scoped pre-state; no canonical pre-create |
| D-15 | Output ownership | many direct canonical writes | many direct canonical writes | late writes/races can corrupt later phases | stage, parse, CAS publish, PhaseIO incorporate |
| D-16 | Validation | standard artifact thresholds | Codex-specific lower summary/build byte floors and generated leftovers exist | lower quality can be accepted as complete | one semantic schema and threshold |
| D-17 | Completion markers | Claude PTY status/turn semantics | marker assumptions bypassed for Codex | backend-specific “done” meaning | completion only after transaction closure and parse |
| D-18 | Paths | legacy `~/.claude` references and canonical Plamen home | Codex rewrites to `~/.codex/plamen` | path rewrite can alter prompt meaning/reachability | logical path manifest; no backend semantic rewrite |
| D-19 | Telemetry | Claude JSON envelope/cache and PTY parser | Codex JSONL token/cost parser | incompatible fields, no common reservations | normalized resource and transport receipts |
| D-20 | Config | backend chosen once; legacy Claude terminal procedure | wizard/flags select Codex; generated adapter differs from driver | config does not describe semantic profile/capabilities | versioned backend policy and explicit migration |
| D-21 | Overrides | only skeptic effectively consults phase override | unavailable override silently falls back | launch receipt and actual backend can diverge | remove silent override; create generation amendment |
| D-22 | Resume | current backend-bound config/checkpoint | backend can be changed or fallback state injected | “resume” can become a new audit destructively | backend switch is explicit new generation/fork |
| D-23 | Fuzz/testing | Claude workers may use shell/test tools under phase policy | Codex has broad shell access and different working-dir handling | proof opportunity differs | driver-owned native command capability |
| D-24 | Concurrency | pools commonly run 3–4 leaves | serial fanout or up to six nested children | wall time and attention differ | same semantic roster and A/B scheduler cap |
| D-25 | Installed adapter | Claude runtime rules are directly consumed | Codex roles/MCP config are generated but ignored by live exec | documentation is mistaken for enforcement | mark adapter as interactive shell support, not driver authority |

No parity claim is permitted while a mandatory row is unresolved. Operational audits may run with debt, but their reports and run manifests must say they are not parity-eligible.

---

## 7. Target data model

### 7.1 Identity hierarchy

Use separate semantic and execution identities:

```text
run_id
  semantic_plan_generation
    phase_semantic_id
      roster_id
        semantic_work_unit_id
          backend_arm_id
            execution_generation
              attempt_id
```

The current `PhaseIOContract.key` includes backend. Keep `plamen.phase_io.v1` readable, but add a v2 identity split:

- `semantic_work_unit_key`: pipeline/mode/ecosystem/phase/work-unit/semantic-generation
- `execution_work_unit_key`: semantic key/backend-arm/execution-generation
- `attempt_key`: execution key/attempt

This allows two backends to prove that they executed the same semantic unit without pretending that their executable/model/transport receipts are identical.

### 7.2 `SemanticWorkPlan`

Create `scripts/semantic_work_plan.py` with canonical JSON schema `plamen.semantic-work-plan.v1`.

Required fields:

```json
{
  "schema": "plamen.semantic-work-plan.v1",
  "run_id": "RUN_ID",
  "pipeline": "sc",
  "mode": "thorough",
  "ecosystem": "evm",
  "semantic_generation": 1,
  "phase_semantic_id": "depth",
  "roster_id": "depth.g1",
  "roster_position": 3,
  "roster_denominator": 12,
  "semantic_work_unit_id": "depth.token-flow.003",
  "role_id": "depth.token-flow",
  "assignment_id": "depth-findings-token-flow",
  "source_snapshot_digest": "sha256",
  "deterministic_fact_snapshot_digests": ["sha256"],
  "semantic_input_manifest_digest": "sha256",
  "semantic_prompt_snapshot_digest": "sha256",
  "methodology_bundle_digest": "sha256",
  "obligation_bundle_digest": "sha256",
  "output_contract_digest": "sha256",
  "tool_capability_manifest_digest": "sha256",
  "resource_grant_digest": "sha256",
  "child_policy": "DRIVER_ONLY_NO_MODEL_CHILDREN",
  "retry_policy": {
    "max_attempts": 2,
    "same_prompt": true,
    "same_model_capability_tier": true,
    "same_tools": true,
    "model_change_requires_new_generation": true
  },
  "completion_policy": {
    "requires_process_scope_empty": true,
    "requires_stream_eof": true,
    "requires_parser_acceptance": true,
    "requires_exact_output_denominator": true,
    "requires_phase_io_incorporation": true
  },
  "semantic_digest": "sha256"
}
```

Rules:

- Canonical UTF-8 JSON, sorted keys, LF, no floats, no timestamps in the digest.
- The plan is immutable after the first arm launches.
- All workers, including planners, assessors, report writers, native fuzz runs, repair workers, and recovery workers, have plans.
- Conditional workers are declared as dormant roster slots or are added through a content-addressed roster amendment derived only from backend-neutral evidence.
- A backend is not a field in the semantic digest.
- Concurrency is a scheduler constraint, not a change to the roster.
- A prompt cannot grant additional children, tools, files, outputs, or retries beyond the plan.

### 7.3 `SemanticPromptSnapshot`

Create `scripts/semantic_prompt_snapshot.py` with schema `plamen.semantic-prompt-snapshot.v1`.

It contains:

- exact canonical prompt bytes;
- ordered semantic sections and section digests;
- exact methodology file identities, sizes, and hashes;
- exact obligation and assignment IDs;
- logical input/output URIs;
- output schema and completion language;
- prompt compiler code digest and compiler version;
- plan digest.

The semantic prompt uses provider-neutral nouns:

- “worker,” not Claude, Codex, Task, Agent, or `spawn_agent`;
- “driver,” not parent model;
- “assigned output,” not apply-patch workaround;
- “request a native capability through the assigned request artifact,” not run an arbitrary shell;
- logical paths such as `workspace://source/...`, `artifact://input/...`, `methodology://...`, and `artifact://output/...`.

It contains no PTY markers, CLI flags, model names, provider-specific tool names, home-directory rewrites, or session-management prose.

### 7.4 `TransportLaunchPlan`

Create `scripts/backend_transport.py` with schema `plamen.transport-launch-plan.v1`.

This backend-specific record binds:

- semantic plan and prompt digests;
- backend and adapter version;
- exact model ID;
- model capability tier;
- reasoning configuration and whether it is provider-controlled;
- executable path and executable hash;
- exact argv and argv digest;
- exact environment-name allowlist and value digests without secret values;
- cwd and logical-path mapping;
- stdin source and digest;
- stream format and byte ceilings;
- transport overlay and digest;
- process-containment strategy;
- backend capability preflight digest;
- timeout and cancellation behavior.

The overlay may say how to read the prompt, where logical paths are mounted, and how the provider signals a completed turn. It may not add or remove methodology, analysis steps, tools, outputs, children, or quality requirements. A validator rejects overlays containing semantic directives or unregistered path grants.

### 7.5 Resource grant

Adopt the adaptive-attention resource unit:

- 1 analysis unit (AU): up to 65,536 input tokens, 8,192 output tokens, 24 brokered tool calls, one bounded timeout.
- Proof-capable worker: 2 AU, up to 131,072 input, 12,288 output, 48 tool calls.
- Report body worker: explicit output allocation with at most 12 tool calls unless its plan says otherwise.
- Minimum runnable channel: 32,768 input and 2,048 output.

The grant must separately bind:

- maximum input tokens;
- maximum output tokens;
- maximum tool requests by capability;
- maximum native command count and native wall time;
- model attempts;
- total semantic timeout;
- stream byte ceilings;
- scheduler concurrency class;
- cache policy.

Legacy timeout scaling remains untouched in `legacy_claude_v1`. In a paired `semantic_v1` experiment, Claude and Codex receive the same grant; the current Codex 3× timeout multiplier is forbidden. An operational, non-paired profile may use a larger transport grace period, but that grace is recorded separately and cannot expand semantic token/tool/native budgets.

---

## 8. Backend capability and model policy

### 8.1 Capability registry

Create `scripts/backend_capability_registry.py`. Every adapter must preflight and issue a content-addressed receipt for:

- exact model availability;
- context and output ceilings;
- controllable reasoning modes;
- tool-call/event observability;
- filesystem enforcement;
- network enforcement;
- MCP/provider availability;
- native command broker availability;
- PTY or headless transport;
- stream and usage telemetry;
- process-tree containment on the current OS;
- resume/session capability;
- provider account mode, such as API key versus ChatGPT entitlement.

Capability states are:

- `SUPPORTED_AND_ENFORCED`
- `SUPPORTED_OBSERVED_ONLY`
- `UNSUPPORTED`
- `UNAVAILABLE_AT_PREFLIGHT`
- `UNKNOWN_BLOCKED`

Only `SUPPORTED_AND_ENFORCED` satisfies a mandatory tool or containment grant in strict parity mode. “Observed only” is debt because post-hoc detection does not prevent cross-arm information or write access.

### 8.2 Semantic model tiers

Replace provider-analogy branching with semantic tiers:

| Tier | Intended work | Minimum capability |
|---|---|---|
| `R3_FRONTIER_REASONING` | depth, high-stakes verification, semantic consolidation, adjudication | strongest approved reasoning model, large context/output, proof tools where planned |
| `R2_STANDARD_REASONING` | recon, breadth, repair, ordinary verification, report bodies | standard approved reasoning, full planned tool support |
| `R1_ECONOMY_STRUCTURED` | deterministic-format assistance, bounded routing/projection | reliable schema adherence; no substitution for reasoning-heavy work |
| `N0_NATIVE_DETERMINISTIC` | graph, parser, build, test, gate, merge | no model invocation |

Initial backend mappings may use current defaults as candidates:

- Claude: Opus-class → `R3`, Sonnet-class → `R2`, Haiku-class → `R1`
- Codex: configured GPT-5.5-class → `R3`, GPT-5.4-class → `R2`, GPT-5.4-mini-class → `R1`

These are not automatic truths. The resolved configuration must bind an exact model ID, supported context/output ceilings, reasoning mode, and tool capability receipt. Environment aliases are resolved once before the semantic roster is armed.

### 8.3 Reasoning mode

`model_reasoning_effort` is part of the transport plan when the provider supports it. If one backend cannot expose or control an equivalent mode:

- strict per-agent parity uses the strongest common controllable setting;
- otherwise the work unit is marked `REASONING_CONTROL_UNMATCHED` and excluded from strict A/B acceptance;
- the driver does not infer equality from model marketing tiers.

The current Codex behavior that sets high effort only for selected o-series model IDs must not silently continue under `semantic_v1`. The capability preflight decides support from the locally installed CLI/provider contract and records the result.

### 8.4 Fallback rules

The following are prohibited within a paired generation:

- unknown alias → Sonnet mapping;
- unavailable model → lower model;
- capacity error → another model;
- ChatGPT rejection → omit `--model`;
- backend override unavailable → configured backend;
- model-specific prompt shortening that changes obligations.

Allowed responses are:

1. retry the exact model under the exact attempt policy;
2. pause for quota/capacity;
3. close the attempt and create explicit debt;
4. with user/policy authority, create a new execution generation with a new model receipt.

A new generation is never compared as if it were the original paired arm.

---

## 9. Tool, MCP, network, filesystem, and fuzz parity

### 9.1 One semantic tool manifest

Generalize the existing Claude exact-tool policy into `ToolCapabilityManifest v2`, independent of backend. It binds:

- exact readable semantic inputs and their hashes;
- read-only source and methodology roots;
- exact writable attempt outputs;
- forbidden inputs and cross-arm directories;
- allowed search roots;
- allowed capability names and call ceilings;
- network/MCP policy;
- native command recipes;
- unknown-tool policy `DENY`;
- receipt directory;
- plan, backend arm, generation, and attempt identities.

Capability names are semantic:

- `SOURCE_READ`
- `SOURCE_SEARCH`
- `METHODOLOGY_READ`
- `ASSIGNED_OUTPUT_WRITE`
- `EXTERNAL_PRECEDENT_QUERY`
- `STATIC_ANALYZER_QUERY`
- `NATIVE_BUILD`
- `NATIVE_TEST`
- `NATIVE_FUZZ`
- `VERSION_PROBE`

Claude `Read`, `Grep`, `Write`, Codex shell/search/apply-patch, and MCP tool names are transport implementations of those grants. They are not the plan vocabulary.

### 9.2 Enforceable attempt view

Each attempt receives an isolated view:

```text
attempt/
  source/            immutable snapshot, read-only
  methodology/       exact content-addressed bundle, read-only
  inputs/            exact PhaseIO inputs, read-only
  outputs/           only assigned paths, writable
  requests/          bounded native/external tool requests, writable
  receipts/          supervisor-only
  streams/           supervisor-only
```

The worker cannot see:

- another backend arm;
- another attempt;
- canonical scratchpad outputs not declared as inputs;
- ground truth;
- user Downloads;
- repository control files outside the snapshot;
- supervisor receipts;
- secrets except through brokered capability invocation.

On Windows, use a suspended child plus Job Object and an ACL/constrained workspace prepared before resume. On Linux, use an owned cgroup/process group and read-only bind/projection where available. A platform without enforceable containment records platform debt and cannot pass strict parity.

### 9.3 Claude adapter enforcement

The Claude adapter may combine:

- PreToolUse hook generated from the neutral manifest;
- `--disallowedTools` as defense in depth;
- isolated attempt view;
- exact write receipts;
- PTY or headless framing.

The existing exact Claude hook is currently limited to selected consumers and hardcodes backend `claude`. It must become a neutral policy compiler used by every model worker.

### 9.4 Codex adapter enforcement

`semantic_v1` must stop using `--dangerously-bypass-approvals-and-sandbox` as the parity path. It must launch inside the constrained attempt view with the strongest locally enforceable noninteractive sandbox. If the installed Codex CLI cannot enforce the manifest:

- mark `CODEX_TOOL_ENFORCEMENT_UNSUPPORTED`;
- do not call the arm parity-eligible;
- do not compensate with prompt language.

`--ignore-user-config` and `--ignore-rules` may remain useful for reproducibility, but then every required MCP/tool setting must be supplied by the driver or broker. Generated `~/.codex/config.toml`, agent TOMLs, and AGENTS rules are not part of the live worker contract.

### 9.5 MCP and external research

The current Codex path cannot use generated MCP servers because it ignores user config. Web fallback is not semantically equivalent.

Implement one of two explicit policies:

1. **Strict intersection policy**
   - Disable model-direct MCP/web for both arms.
   - Feed both workers the same pre-recorded, content-addressed external evidence packet.
   - Use this for parity fixtures and A/B acceptance.

2. **Driver-brokered live provider policy**
   - A worker emits a bounded query request with a semantic capability ID.
   - The driver executes the same pinned provider for either backend.
   - Response bytes, timeout, provider version, and fallback are recorded.
   - MCP timeout follows the methodology rule: no retry; record timeout and use only a predeclared common fallback.

If live provider capability differs between arms, both paired workers receive the common intersection or the channel is blocked. One backend never gains an extra research agent or web search to compensate.

### 9.6 Native build, test, and fuzz

Models do not receive unrestricted shell authority in parity mode. They produce a structured request against a predeclared recipe. The driver launches a `NativeCommandAdapter` WorkPlan with:

- exact toolchain executable/hash/version;
- exact cwd and source snapshot;
- exact command template and validated parameters;
- network policy;
- input/output denominator;
- timeout and stream limits;
- process-tree closure;
- result parser digest.

Fuzzing uses the same prepared fuzz workspace, seed corpus, seed value when supported, duration, workers, and toolchain for both arms. The model may propose properties/tests, but execution is backend-neutral. Existing `fuzz_workspace_authority` Job handling should be folded into the universal owned-process primitive rather than remain a second process authority.

---

## 10. Driver-owned fanout and adaptive attention

### 10.1 No nested audit agents

In `semantic_v1`, `child_policy` is always `DRIVER_ONLY_NO_MODEL_CHILDREN` for audit work. The driver must expand:

- recon roles;
- breadth manifest rows;
- rescan rows;
- per-contract work;
- depth and niche roles;
- invariant/fuzz roles;
- RAG/precedent work;
- chain shards;
- verifier shards and recovery;
- skeptic/judge/adjudication;
- report index/body/tier/assembly roles.

The current `CODEX_MULTI_AGENT_PHASES` prompt mechanism becomes legacy-only. Codex `spawn_agent` cannot satisfy parity because child model, sandbox, prompts, outputs, process lifetime, and token accounting are inherited or hidden.

### 10.2 Roster construction

The roster is compiled from:

- source snapshot and scope;
- mode/ecosystem;
- phase registry;
- deterministic typed facts;
- security-obligation and methodology authorities;
- exact manifest rows;
- adaptive-attention policy;
- explicit unsupported-debt decisions.

It is not compiled from backend identity.

Adaptive amendments use a monotonic `RosterAmendment`:

- previous roster digest;
- backend-neutral triggering evidence digest;
- newly added dormant/active semantic unit IDs;
- resource transfer;
- reason code;
- new roster digest.

Raw positive finding count is not an amendment authority. This retires the old “more prose findings → more wave work” coupling.

### 10.3 Same roster versus result-dependent phases

For a production end-to-end run, later verifier/report rosters legitimately depend on earlier candidate identities, so two independent models may produce different later workloads. This is not a transport-parity test.

Use three paired experimental strata:

1. **Discovery parity**
   - identical source, facts, obligations, and fixed discovery roster;
   - compare candidate/negative/coverage outputs.

2. **Verification parity**
   - identical blinded candidate queue supplied to both arms;
   - identical verifier roster and native proof grants.

3. **Report parity**
   - identical verified typed ledger supplied to both arms;
   - identical report roster and output contract.

A separate full-pipeline A/B may compare operational quality under equal policy and maximum resources, but must report downstream roster divergence as an outcome rather than claim exact per-worker parity.

### 10.4 Scheduler

The scheduler:

- persists the full roster before launch;
- uses the same concurrency cap in strict paired runs;
- starts each unit through WorkerTransaction;
- waits for every started unit;
- proves the active registry empty;
- records unlaunched required units as debt;
- cannot commit a parent phase while any required unit is active, unincorporated, or ambiguous.

Concurrency may differ in ordinary non-paired operational mode if recorded, but it never changes semantic roster, per-worker grant, or completion denominator.

---

## 11. WorkerTransaction and PhaseIO integration

### 11.1 Required order

Every provider path follows:

```text
compile immutable plan and roster
  -> bind prompt, methodology, inputs, outputs, tools, resources
  -> create unique attempt staging and owned OS scope
  -> arm durable launch receipt
  -> launch
  -> join/terminate and prove entire scope empty
  -> drain streams to EOF
  -> parse exact attempt outputs
  -> validate tool and resource receipts
  -> compare-and-swap publish
  -> persist completion or debt
  -> PhaseIO incorporate
  -> aggregate
  -> phase gate
  -> phase commit
```

No parse, validation, canonical publication, or PhaseIO incorporation occurs after a provisional PTY turn end but before process-scope closure.

### 11.2 Extend the current worker receipt substrate

`worker_execution_receipts.py` already provides important primitives:

- immutable bound inputs;
- exact launcher/backend/model intent;
- exact expected output denominator;
- bounded streams;
- owned process tree;
- arm-before-launch;
- immutable completion/debt;
- compare-and-swap publication;
- replay.

Extend or wrap it with:

- semantic plan/generation/roster identities;
- backend arm and attempt identities;
- PTY lifecycle adapter consumption;
- native provider capability;
- exact resource counters;
- tool receipt denominator;
- zero-active-descendant proof;
- semantic/transport prompt split;
- multiple attempts without canonical-name reuse;
- PhaseIO incorporation receipt.

Do not create a second “parity runner” with weaker guarantees.

### 11.3 PTY behavior

`ClaudePtyAdapter` is a codec:

- spawn/send/bootstrap;
- capture transcript;
- identify provisional turn completion;
- expose provider rate-limit/session observations;
- request graceful termination.

WorkerTransaction owns:

- OS process scope;
- cancellation;
- descendant closure;
- stream EOF;
- output publication;
- completion.

A PTY “complete” marker is never a completion receipt by itself.

### 11.4 Attempt and retry semantics

Each attempt has a unique staging directory and output names. Canonical output identities belong only to the plan.

A retry:

- binds the same semantic plan, prompt, methodology, inputs, tools, resource ceiling, model capability tier, and output assignment;
- does not read partial output from a failed attempt unless a predeclared recovery plan makes it an immutable input;
- cannot reuse a canonical attempt name;
- publishes only one winning attempt;
- records all failed attempts and consumed budget.

Changing backend, model ID, reasoning tier, capability set, prompt, methodology, source, or output schema creates a new generation.

### 11.5 Phase commit

Phase commit requires:

- all required roster units terminal;
- all successful units replay-valid;
- all expected PhaseIO incorporations present;
- all required outputs at the exact denominator;
- no active process scope;
- no late-write or unowned-write debt;
- all mandatory tool/resource capability receipts valid;
- aggregate and gate inputs bound to the incorporated outputs;
- parity status recorded when the run is a paired experiment.

---

## 12. Backend adapters

Define a narrow interface:

```text
BackendAdapter.preflight(capability_request) -> BackendCapabilityReceipt
BackendAdapter.compile_transport(semantic_snapshot, attempt_view) -> TransportLaunchPlan
BackendAdapter.launch(transport_plan, owned_scope) -> TransportHandle
BackendAdapter.observe(handle) -> TransportObservation
BackendAdapter.request_stop(handle) -> StopObservation
BackendAdapter.decode_usage(streams) -> NormalizedUsageObservation
```

Adapters do not:

- choose workers;
- choose methodology;
- choose outputs;
- add prompt obligations;
- grant tools;
- select a fallback model;
- publish artifacts;
- decide completion;
- retry.

### 12.1 `ClaudePtyAdapter`

Preserves the legacy PTY transport features:

- winpty or POSIX session startup;
- bootstrap framing;
- transcript and marker decoding;
- quiescence/rate-limit observations;
- graceful stop.

For `semantic_v1`, it runs one driver-owned leaf. Model child tools are denied.

### 12.2 `ClaudeHeadlessAdapter`

Uses one `claude -p` subprocess and JSON envelope. It receives the same semantic snapshot and attempt view as PTY/Codex. Headless versus PTY is a transport choice recorded in the launch receipt, not a prompt-semantic branch.

### 12.3 `CodexExecAdapter`

Uses one `codex exec` subprocess per driver-owned leaf:

- exact model required;
- JSONL event parsing;
- no model-owned children;
- no account-default model retry;
- reproducible user-config/rules policy;
- constrained attempt view;
- enforceable common capabilities;
- exact output/stream receipts.

Current robustness config such as auto-compaction and service tier remains transport metadata. It cannot expand prompt context or silently change a model. Any compaction observation is included in telemetry.

### 12.4 `NativeCommandAdapter`

Runs pinned deterministic tools and approved test/fuzz recipes through the same transaction and process containment. Native outputs are reusable across backend arms only when source, toolchain, command, environment, and parser digests match exactly.

---

## 13. Prompt compiler cutover

### 13.1 Compiler stages

1. `PhaseSemanticCompiler`
   - resolves phase, role, manifest row, obligations, outputs, and resources.

2. `MethodologyBundleCompiler`
   - resolves canonical files under Plamen home;
   - maps legacy `~/.claude/` references once into content-addressed methodology identities;
   - rejects unresolved or wrong-ecosystem skills.

3. `SemanticPromptCompiler`
   - produces provider-neutral prompt bytes;
   - includes exact scope and output assignment;
   - has no transport language.

4. `TransportOverlayCompiler`
   - maps logical paths and completion framing;
   - cannot edit semantic bytes.

5. `PromptParityValidator`
   - proves semantic snapshot equality across backend arms;
   - validates overlay field allowlist.

### 13.2 Path resolution

The semantic compiler uses the canonical repository/installed Plamen root and stores content digests. Methodology files may retain legacy textual references internally, but cross-references are resolved into the bundle manifest before launch.

Do not run broad string replacements over the final prompt. `_translate_prompt_for_codex` remains `legacy_v1` only and is deleted from `semantic_v1` call paths.

Transport overlays map logical URIs to the attempt view. A model never needs to know whether the installed methodology is under `~/.claude`, `~/.codex/plamen`, a symlink, or a copied install.

### 13.3 Output contract

The semantic prompt names only assigned logical outputs. If a provider requires files to exist before editing, the attempt-view builder uses the same pre-state for both arms and binds it in the output contract. Canonical scratchpad files remain absent until transaction publication.

There are no Codex-only relaxed minimum bytes, automatic leftovers, or alternate format assumptions. Provider-tolerant parsing may normalize harmless envelope syntax, but the accepted semantic schema is identical.

---

## 14. Configuration and CLI migration

### 14.1 Configuration schema

Add a versioned block while keeping existing keys readable:

```json
{
  "semantic_plan_version": "semantic_v1",
  "backend_policy": {
    "primary_backend": "claude",
    "transport": "pty",
    "parity_mode": "OFF",
    "strict_capability_intersection": true,
    "allow_operational_debt": false
  },
  "model_capability_map": {
    "R3_FRONTIER_REASONING": {
      "claude": {"model": "EXACT_ID", "reasoning": "provider-default-bound"},
      "codex": {"model": "EXACT_ID", "reasoning": "high"}
    },
    "R2_STANDARD_REASONING": {},
    "R1_ECONOMY_STRUCTURED": {}
  },
  "resource_policy": {
    "profile": "adaptive-au-v1",
    "strict_pair_concurrency": 2
  },
  "tool_policy": {
    "profile": "brokered-intersection-v1"
  },
  "resume_policy": {
    "backend_switch": "NEW_GENERATION_ONLY"
  }
}
```

Rules:

- Existing configs without `semantic_plan_version` remain `legacy_claude_v1` or their originally recorded backend legacy profile. They are not upgraded in place.
- New semantic configs freeze the complete policy and exact model maps into the run manifest.
- Environment variables may seed a new config but are resolved and hashed before launch; resume does not re-resolve them.
- `_codex_phase_model_fallbacks`, `_codex_model_unavailable`, `_codex_model_fallback`, and `_codex_skip_model` are legacy runtime state only and prohibited in a strict semantic run.
- `phase_backend_overrides` is deprecated. A phase backend change requires an explicit generation amendment.

### 14.2 CLI

Keep compatibility:

- `--claude`
- `--codex`
- existing wizard backend choice
- existing `resume`

Add:

- `--semantic-profile legacy_claude_v1|semantic_v1`
- `--transport pty|headless|exec`
- `--parity-profile off|structural|matched-ab`
- `--capability-policy strict-intersection|operational-debt`
- `--fork-backend-generation claude|codex`
- `--explain-backend-capabilities`

The wrapper writes configuration; the deterministic driver still owns phases. A CLI flag never directly mutates a live checkpoint.

### 14.3 Generated Codex adapter

Reclassify generated Codex files:

- interactive Plamen skill/command entry points;
- install-time methodology linkage;
- optional human Codex configuration.

They are not production driver worker policy. Documentation must say that `semantic_v1` launches receive their full plan, tools, and transport settings from the driver, even when `--ignore-user-config` is used.

Remove stale claims, especially automatic MCP/web equivalence and unverified Bake behavior.

---

## 15. Resume, migration, and cross-backend generations

### 15.1 Same-backend resume

Resume loads:

- immutable run/source/config snapshot;
- semantic plan generation;
- roster/amendments;
- per-unit completion/debt;
- PhaseIO incorporation;
- active-scope reconciliation.

It may:

- reuse replay-valid completions;
- retry incomplete units under the original retry plan;
- regenerate supervisor views from immutable manifests.

It may not:

- archive or clear an existing scratchpad automatically;
- launch new recon because a later checkpoint is ambiguous;
- recompute model aliases from current environment;
- adopt unincorporated canonical files;
- rewrite a backend/model within an attempt.

### 15.2 Backend switch

Switching Claude ↔ Codex is never an identical resume.

An explicit backend fork:

1. preserves the old arm and every receipt;
2. freezes a new backend arm and execution generation;
3. reuses only deterministic/native facts whose complete provider bindings replay;
4. reruns model work under the new backend;
5. records mixed-provenance upstream inputs if the user intentionally continues rather than forks from a common checkpoint;
6. marks mixed operational continuations ineligible for strict parity.

For matched A/B, create two isolated arm directories from the same prepared semantic bundle before either model launches. Neither arm may read the other.

### 15.3 Legacy migration

Migration is explicit and non-destructive:

- `legacy_claude_v1` checkpoints remain readable indefinitely.
- A migration tool produces a proposal and receipt; it does not overwrite config/checkpoint.
- If exact semantic identities cannot be derived from legacy artifacts, record `LEGACY_IDENTITY_UNRESOLVED` and rerun the affected unit in a new semantic generation.
- A failed migration leaves the legacy run untouched.

---

## 16. Parity receipts and normalized telemetry

### 16.1 Receipt set

Persist canonical, replayable records:

1. `semantic_plan_receipt.json`
2. `semantic_roster_receipt.json`
3. `semantic_prompt_snapshot.json`
4. `methodology_bundle_receipt.json`
5. `backend_capability_receipt.<arm>.json`
6. `transport_launch_plan.<arm>.<attempt>.json`
7. `worker_arm/completion/debt` receipts
8. `tool_capability_receipt.<attempt>.json`
9. `resource_usage_receipt.<attempt>.json`
10. `phase_io_incorporation_receipt.json`
11. `phase_parity_receipt.json`
12. `run_parity_receipt.json`

### 16.2 Phase parity receipt

It compares:

- semantic plan digest;
- roster digest and ordered unit IDs;
- per-unit semantic prompt digest;
- methodology/obligation/output/tool/resource digests;
- model capability tier;
- maximum attempts;
- common capability state;
- completion/incorporation status;
- actual normalized usage;
- debt codes;
- exclusions from the paired denominator.

Possible states:

- `STRUCTURALLY_MATCHED`
- `STRUCTURALLY_MATCHED_WITH_USAGE_VARIANCE`
- `UNMATCHED_CAPABILITY`
- `UNMATCHED_ROSTER`
- `UNMATCHED_PROMPT`
- `UNMATCHED_RESOURCE_GRANT`
- `UNMATCHED_MODEL_TIER`
- `INCOMPLETE_ARM`
- `NOT_PARITY_ELIGIBLE`

### 16.3 Normalized telemetry

Normalize without erasing provider detail:

- input, cached input, cache creation, and output tokens;
- context-window and output ceilings;
- reasoning configuration;
- tool requests by semantic capability;
- native command count/time;
- turns/compactions;
- wall time and transport grace;
- attempts/retries;
- stream bytes and overflow;
- model and provider stop reasons;
- rate/capacity/auth outcomes;
- process-tree termination;
- parse/publication/PhaseIO timings;
- estimated cost with pricing-source version.

The existing Markdown cost ledger remains a human view. It is not the parity authority.

---

## 17. Unsupported-capability debt registry

Create stable debt codes and fail-closed effects:

| Debt code | Current cause | Strict parity effect | Closure condition |
|---|---|---|---|
| `CX_NESTED_CHILD_UNOWNED` | Codex coordinator spawns children | block affected phase | driver-owned leaf roster only |
| `CX_MCP_NOT_LOADED` | `--ignore-user-config` disables generated MCP | block live-MCP channel or use common recorded packet | driver-brokered identical provider |
| `CX_TOOL_POLICY_UNENFORCED` | dangerous sandbox bypass, no neutral hook | block arm | constrained view plus receipts |
| `CX_MODEL_DEFAULT_UNKNOWN` | retry without `--model` | block attempt | exact model receipt |
| `CX_MODEL_FALLBACK_MUTATION` | capacity/unavailable fallback | exclude generation | explicit new generation |
| `CX_REASONING_CONTROL_UNKNOWN` | model reasoning effort unavailable/unbound | block strict tier match | capability receipt or common lower tier |
| `CX_TIMEOUT_MULTIPLIER` | Codex 3× phase timeout | block matched budget | equal semantic timeout |
| `CX_SERIAL_FANOUT_DRIFT` | serial fanout versus Claude pool | block strict scheduler parity when material | same driver scheduler cap |
| `CX_PROMPT_TRANSLATION_DRIFT` | `_translate_prompt_for_codex` alters semantics | block unit | identical semantic snapshot |
| `CX_OUTPUT_PRECREATE_DRIFT` | Codex-only pre-created artifacts | block unit | identical attempt pre-state |
| `CX_VALIDATOR_RELAXATION` | lower Codex byte floors/auto leftovers | block phase | shared validator |
| `CX_PATH_REWRITE_DRIFT` | backend home rewrite in prompt | block unit | logical path manifest |
| `CX_GENERATED_ADAPTER_UNUSED` | role/MCP TOMLs ignored by live exec | informational, blocks claims based on them | docs/runtime alignment |
| `MODEL_TIER_UNMATCHED` | Claude promotion absent on Codex | block unit | pre-backend tier resolution |
| `MCP_PROVIDER_UNMATCHED` | different external providers/fallbacks | block channel | common provider/recording |
| `NATIVE_TOOLCHAIN_UNMATCHED` | build/fuzz versions or grants differ | block proof comparison | exact native provider receipt |
| `PTY_DESCENDANT_CLOSURE_UNPROVEN` | PTY scope can outlive root | block completion | P0-AM closure proof |
| `PROCESS_CONTAINMENT_PLATFORM_DEBT` | unsupported OS containment | block strict parity | enforced owned scope |
| `CROSS_BACKEND_MIXED_PROVENANCE` | mid-run backend continuation | mark run non-paired | fork from common snapshot |
| `LEGACY_IDENTITY_UNRESOLVED` | migration cannot bind exact semantic unit | no completion reuse | rerun in new generation |

Debt is a typed artifact consumed by report assurance. It cannot be hidden by a successful exit code or a syntactically complete report.

---

## 18. Implementation map

### 18.1 New modules

| Module | Responsibility |
|---|---|
| `scripts/semantic_work_plan.py` | semantic identities, plan, roster, amendments, canonical serialization |
| `scripts/semantic_prompt_snapshot.py` | backend-neutral prompt compiler and snapshots |
| `scripts/backend_capability_registry.py` | model/tool/transport/OS capability preflight and debt |
| `scripts/backend_transport.py` | adapter interface and transport launch plan |
| `scripts/backend_claude.py` | PTY/headless adapters |
| `scripts/backend_codex.py` | Codex exec adapter |
| `scripts/native_command_adapter.py` | driver-owned build/test/fuzz/static provider |
| `scripts/tool_capability_manifest.py` | backend-neutral policy, attempt view, receipts |
| `scripts/worker_transaction.py` | universal lifecycle wrapper over the hardened receipt substrate |
| `scripts/parity_receipts.py` | structural/resource/run comparison and replay |
| `scripts/backend_generation.py` | explicit backend/model generation forks and migration receipts |

Names may be consolidated, but authorities must not be duplicated.

### 18.2 Existing modules to change

| Module | Required change |
|---|---|
| `scripts/plamen_types.py` | declare semantic tier/resource/capability metadata independent of backend; preserve legacy phase list |
| `scripts/plamen_prompt.py` | split semantic compiler from legacy transport variants; keep legacy code path |
| `scripts/plamen_driver.py` | compile roster, route every launch through transaction/adapters, remove semantic-mode nested agents/fallbacks/direct writes |
| `scripts/pty_exec.py` | expose codec observations to WorkerTransaction; no ownership claims |
| `scripts/worker_execution_receipts.py` | add semantic/generation/PTY/tool/resource/PhaseIO bindings |
| `scripts/phase_io_contracts.py` | add v2 semantic/execution key split and incorporation receipt |
| `scripts/claude_phase_tool_policy.py` | generalize manifest/compiler; keep Claude hook as adapter implementation |
| `scripts/fuzz_workspace_authority.py` | use common owned-process and transaction authority |
| `scripts/recon_prepass.py` | native provider WorkPlans |
| `scripts/mechanical_verify.py` | native command WorkPlans |
| `scripts/audit_snapshot.py` | freeze semantic policy, backend arms, environment/model mappings; expand exact backend runtime classification |
| `scripts/plamen_validators.py` | remove backend-specific semantic thresholds in `semantic_v1` |
| `plamen.py` | versioned config/CLI, explicit backend generation fork, capability explanation |
| `scripts/codex_adapter.py` | align generated docs with production authority; do not imply roles/MCP are live |
| `docs/codex-backend.md` | replace reduced-fanout/fallback guidance with profile/debt semantics |
| `docs/terminal-legacy-claude-audits.md` | retain immutable legacy procedure and identify profile |

### 18.3 Launch-path migration denominator

Migration is incomplete until all are transaction-backed:

- generic Claude PTY;
- generic Claude headless;
- generic Codex exec;
- recon pool and research wave;
- breadth pool and serial fanout;
- rescan pool;
- depth batch and serial fanout;
- dynamic verifier and recovery;
- chain-tail isolated model attempts;
- missing-only continuation;
- application skeptic and adjudication providers;
- report body/index/repair providers;
- recon native prepass;
- mechanical verification;
- fuzz workspace execution;
- supply-chain/static providers;
- all CPG providers.

The driver should generate a checked `provider_launch_inventory.json` from the dispatch registry. A source scan for raw `Popen`/PTY creation outside approved adapter modules fails CI.

---

## 19. Phased implementation order

### Stage 0 — freeze and observe legacy

- Assign `legacy_claude_v1`.
- Capture exact prompt/argv/model/tool/output/checkpoint fixtures for representative Claude PTY and headless phases.
- Add source-level guard that semantic modules are not imported into legacy launch construction unless observational only.
- Preserve the terminal legacy audit artifacts without resuming them.

Exit: legacy fixtures prove no behavior change.

### Stage 1 — complete P0-AM and P0-AE prerequisites

- Cut every launch path over to owned process scope, unique attempt staging, closure proof, and CAS.
- Finish PhaseIO incorporation/commit authority.
- Eliminate `shutdown(wait=False)` and late canonical writes.
- Make retries exact and generation-aware.

Exit: fault injection proves no descendant or write survives completion/timeout/cancel.

### Stage 2 — semantic schemas and shadow compiler

- Implement plan/roster/prompt/capability/resource schemas.
- Compile shadow plans beside legacy runs without changing launch bytes.
- Compare declared roster to observed worker launches.

Exit: shadow denominator is complete and replayable for every phase/provider.

### Stage 3 — adapters and common tool boundary

- Implement Claude PTY/headless, Codex exec, and native adapters.
- Build isolated attempt view and neutral tool manifest.
- Remove model-owned children in semantic mode.
- Add strict capability preflight/debt.

Exit: a synthetic worker executes identical semantic bytes on both backends with zero unregistered access.

### Stage 4 — migrate phase families

Migrate in bounded slices:

1. one single-leaf analysis phase;
2. breadth row fanout;
3. depth roles and native proof requests;
4. recon/rescan;
5. verification queue/shards/recovery;
6. chain;
7. report index/body/assembly;
8. all mode/ecosystem variants.

Each slice requires legacy non-regression and structural parity before the next.

### Stage 5 — adaptive attention and CPG inputs

- Compile attention roster before transport.
- Bind typed graph slices as identical PhaseIO inputs.
- Ensure graph/attention 2×2 experiments use equal backend/model/tool/token budgets.

Exit: backend choice cannot alter graph facts, channel selection, or resource grants.

### Stage 6 — config, resume, and cross-backend generations

- Add versioned config and explicit migration.
- Add isolated paired arms and new-generation backend switch.
- Prove non-destructive restart/replay.

Exit: identical resume launches no new recon; backend switch cannot masquerade as resume.

### Stage 7 — parity receipts and validation

- Add normalized telemetry and structural receipts.
- Run the fixture/fault/canary matrix.
- Produce a handoff package for user-run <PRIVATE_AUDIT_TARGET> and <PRIVATE_REGRESSION_TARGET>.

---

## 20. Validation blueprint

No tests were run while producing this document. The following is the required future matrix.

### 20.1 Schema and deterministic unit tests

- canonical JSON round-trip and duplicate-key rejection;
- semantic digest excludes backend/transport and includes every semantic grant;
- execution digest includes exact backend/model/argv/environment names;
- no floats/timestamps in authority digests;
- roster order/denominator stable across process count and backend;
- amendment monotonicity;
- v1 PhaseIO read compatibility and v2 key separation;
- exact model alias resolution and unknown-alias rejection;
- overlay semantic-directive rejection;
- logical path resolution and traversal/case-collision rejection.

### 20.2 Prompt parity tests

For every registered model work unit:

- Claude and Codex semantic prompt SHA-256 equal;
- methodology bundle SHA-256 equal;
- obligation/output/tool/resource digests equal;
- transport overlay differs only in allowlisted fields;
- no `Task`, `Agent`, `spawn_agent`, Claude, Codex, PTY, or provider-specific path appears in semantic bytes;
- legacy Claude prompt remains byte-identical under `legacy_claude_v1`.

Extend the existing breadth/depth methodology dispatch tests rather than replacing them.

### 20.3 Roster and phase tests

- all 75 SC and 59 L1 phases map to an explicit provider class;
- every phase/mode/ecosystem produces a complete roster or typed unsupported debt;
- recon counts 2 Light / 4 Core/Thorough where policy requires;
- manifest-driven breadth/rescan rows match exactly;
- depth fixed/conditional roles match exactly;
- verification and report denominators match fixed input ledgers;
- no Codex-only nested unit;
- no Claude-only hidden child;
- same scheduler cap in paired mode.

### 20.4 Tool and containment tests

- unregistered read/write/search/network/native command denied;
- exact input mutation detected;
- methodology wrong-ecosystem access denied;
- cross-arm and cross-attempt access denied;
- output path escape/case collision denied;
- tool call ceilings enforced;
- MCP timeout produces no retry and common fallback receipt;
- Codex sandbox inability produces debt, not prompt-only continuation;
- Claude hook and Codex/native enforcement produce the same semantic decisions.

### 20.5 Worker lifecycle fault tests

- root exits while child keeps writing;
- child creates grandchild;
- timeout;
- cancellation/Esc;
- stream overflow;
- nonzero exit;
- PTY provisional completion then late output;
- output parse failure;
- executable/parser/input changes;
- CAS race;
- publish failure;
- retry after partial write;
- model rate/capacity/auth failure;
- Windows Job, Linux process group/cgroup, and declared platform-debt cases.

Required result: no completion until scope empty; no canonical late write; durable debt on every failure.

### 20.6 Resume and migration tests

- same-backend exact resume reuses only replay-valid work;
- no new recon on a completed upstream checkpoint;
- changed source/config/model/tool/methodology invalidates exact units;
- backend switch requires explicit generation;
- old arm remains intact;
- deterministic native facts reuse only under exact provider digest;
- legacy migration failure is non-destructive;
- mixed backend provenance is visibly non-parity.

### 20.7 Resource and telemetry tests

- equal configured token/output/tool/native/time grants;
- Codex timeout multiplier disabled in paired mode;
- same retry maximum;
- provider usage normalized without inventing missing data;
- account-default/no-model attempt rejected;
- cache policy and warm/cold status recorded;
- all started units counted, including failed attempts.

---

## 21. Synthetic and non-ground-truth canary matrix

### 21.1 Synthetic mechanics fixtures

| Fixture | Ecosystem | Purpose | Expected structural assertions |
|---|---|---|---|
| Minimal vault/share model | EVM | zero-state, donation, rounding, role paths | fixed recon/breadth/depth roster; exact candidate identities retained |
| Cross-domain message router | EVM | replay/domain separation/timing | chain and verification fixed packets |
| PDA/token authority program | Solana | signer/seed/account constraints | ecosystem-specific methodology and native-tool parity |
| Move capability/store model | Aptos/Sui | capability, resource, migration paths | separate provider/methodology routing |
| Storage TTL/auth contract | Soroban | lifecycle and auth | exact state/role obligations |
| Go message-validation service | L1 | codec, limits, concurrency | typed Go facts and fixed L1 roster |
| Rust networking/codec crate | L1 | unsafe/bounds/state machine | SCIP facts and native test parity |
| Detached-child writer | backend-neutral | lifecycle fault | zero late canonical writes |
| MCP timeout recorder | backend-neutral | external provider behavior | identical no-retry debt/fallback |
| Output/case collision fixture | backend-neutral | containment | identical denial and debt |

Synthetic fixtures may include seeded expected conditions because they validate mechanics. They must not contain <PRIVATE_AUDIT_TARGET>/<PRIVATE_REGRESSION_TARGET> material.

### 21.2 Non-ground-truth operational canaries

Use at least four small/medium public or internal projects not present in any evaluation ground-truth corpus:

- one EVM application;
- one non-EVM smart-contract project;
- one Go L1/service codebase;
- one Rust L1/service codebase.

Requirements:

- exact source commit archived before run;
- no audit report, label file, benchmark answer, or known-finding summary in either arm;
- identical docs/scope and deterministic facts;
- arm order randomized;
- evaluator identity blinded until both reports freeze;
- three paired replications where budget permits;
- no cross-arm reads or shared model outputs;
- rate-limited/capacity-fallback runs invalidated before unblinding;
- structural parity evaluated before security quality.

### 21.3 CPG/attention experiment

Use the adaptive blueprint’s 2×2:

- graph off / attention off;
- graph on / attention off;
- graph off / attention on;
- graph on / attention on.

Run backend comparison only after each cell has:

- identical semantic roster policy;
- identical model capability tiers;
- identical per-unit and total AU;
- identical tools/providers;
- identical source/fact snapshots;
- no ground-truth exposure.

Graph facts are prepared once and copied by digest to both arms. Attention channel selection is compiled from common deterministic obligations, not one backend’s findings.

---

## 22. Matched-budget A/B protocol

### 22.1 Preparation

1. Freeze one source and external-input snapshot.
2. Run deterministic preparation once.
3. Compile one semantic experiment bundle.
4. Produce two isolated backend arms.
5. Preflight exact models and capabilities.
6. Fail before model launch if mandatory common capability is missing.
7. Randomize launch order; use the same concurrency cap and cache condition.

### 22.2 Budget matching

Match:

- ordered semantic work units;
- capability tier per unit;
- maximum input/output tokens;
- tool and native command calls;
- timeout;
- attempts;
- total AU;
- external provider packet;
- scheduler concurrency;
- report/verification output schema.

Report both reserved and consumed resources. Equal maximum budget is the authority; actual consumption is an outcome. A backend that fails early does not receive invisible replacement work.

### 22.3 Evaluation strata

Evaluate in this order:

1. structural parity;
2. lifecycle and containment;
3. completion/gate correctness;
4. identity and no-loss accounting;
5. security-quality rubric;
6. cost and latency.

A quality score is inadmissible if structural parity failed.

### 22.4 Blinded quality rubric

For discovery:

- distinct valid candidate coverage;
- security-obligation coverage;
- explicit negative/ruled-out reasoning quality;
- code-location/evidence quality;
- duplicate/noise rate;
- severity not scored as discovery success.

For verification:

- exact candidate denominator;
- reproducible proof attempt;
- execution result honesty;
- negative authority and uncertainty handling;
- no unsupported promotion/demotion.

For reports:

- verified identity retention;
- evidence traceability;
- disposition completeness;
- limitation/debt disclosure;
- no invented claims.

Use paired blinded adjudication and an independent tie-breaker. Predeclare a non-inferiority margin, suggested at five percentage points on the normalized rubric, while requiring zero loss of mandatory seeded fixture obligations and zero lifecycle/identity blockers.

---

## 23. Acceptance gates

### Gate A — legacy Claude preservation

- With an existing config or `legacy_claude_v1`, phase ordering, prompts, resolved models, argv, tool deny lists, output contracts, gates, and resume behavior match the frozen baseline.
- PTY remains the default where it is currently default.
- No Codex parity code changes legacy prompt semantics.
- The terminal 70/75 legacy audit is preserved and not resumed.

### Gate B — structural semantic parity

- 100% paired semantic roster identity and order.
- 100% semantic prompt digest equality.
- 100% methodology, obligation, output, tool, and resource digest equality.
- Zero model-owned audit children.
- Zero silent backend/model/tool fallback.
- Same semantic validator/gate thresholds.
- Every required unit has one terminal completion or typed debt.

### Gate C — lifecycle and PhaseIO

- Every production model/native provider uses WorkerTransaction.
- No active child/process scope at completion or phase commit.
- No canonical write before CAS publication.
- No late write after timeout/cancel/root exit.
- All incorporated outputs replay against completion and PhaseIO receipts.

### Gate D — capability parity

- Mandatory capabilities are `SUPPORTED_AND_ENFORCED` on both arms.
- MCP/web/native fuzz differences are resolved through the common intersection or explicit blocking debt.
- Exact model and reasoning receipts exist.
- The generated Codex adapter is not used as evidence for ignored runtime config.

### Gate E — matched resources

- Same per-unit and total AU.
- Same timeout and retry ceiling.
- Same concurrency in strict paired runs.
- Same external evidence packet and native toolchain.
- No Codex 3× timeout or replacement agents.

### Gate F — no-loss and quality

- No candidate identity, security obligation, candidate negative, independent negative, verification disposition, or report identity is dropped across handoffs.
- All-severity Thorough verification policy remains intact.
- Synthetic mandatory conditions are retained and processed.
- Claude `semantic_v1` is non-regressive against the frozen legacy Claude canary baseline.
- Codex meets the predeclared blinded non-inferiority margin under structurally matched runs.

### Gate G — resume/migration

- Same-backend resume is exact and non-destructive.
- Cross-backend execution is an explicit new arm/generation.
- Legacy configs are never silently upgraded.
- A failed migration or unavailable backend leaves prior state unchanged.

### Gate H — final handoff

- Focused and full suites pass in the implementation environment.
- Fault, migration, resume, cross-OS, and non-GT canary evidence is packaged.
- Unsupported debt is zero for strict parity, or the feature remains non-parity and clearly labeled.
- User receives commands and expected receipts for <PRIVATE_AUDIT_TARGET> and <PRIVATE_REGRESSION_TARGET>; Plamen does not run them during implementation handoff.

---

## 24. Required test/source updates

Retain and expand existing coverage:

- backend methodology dispatch tests: promote row-level parity into all-worker parity;
- effective backend tests: replace silent skeptic override fallback with explicit generation/debt behavior in semantic mode;
- Codex depth fanout tests: require driver-owned roster, model tier per job, transaction publication, and equal scheduling policy;
- phase model promotion tests: assert semantic tier equality before backend mapping;
- PTY execution contract tests: keep legacy variants, add provider-neutral semantic snapshot equality;
- worker execution receipt tests: add PTY, tools, resources, generation, and PhaseIO incorporation;
- Claude phase tool tests: parameterize the neutral policy across Claude and Codex enforcement;
- rescan/recon/depth pool tests: assert exact paired roster;
- snapshot/startup tests: assert arm isolation and non-destructive backend fork;
- validator tests: assert no backend-specific semantic floor in `semantic_v1`.

Add a registry test that enumerates every `SC_PHASES` and `L1_PHASES` entry and fails if it lacks:

- semantic phase metadata;
- provider class;
- roster compiler;
- model capability tier;
- resource profile;
- tool profile;
- output contract;
- retry policy;
- parity eligibility rule.

Add a source-structure test that allows process creation only in reviewed adapter/transaction/supervisor modules.

---

## 25. Rollout and rollback

Rollout is opt-in:

1. ship schemas and shadow receipts;
2. ship `semantic_v1` behind explicit config;
3. run synthetic parity;
4. run non-GT canaries;
5. permit operational opt-in with visible debt;
6. make semantic profile default only after all acceptance gates;
7. retain legacy Claude for at least one release cycle and until byte-regression confidence is high.

Rollback:

- never rewrites semantic/legacy checkpoints;
- selects the prior explicit profile for a new run;
- retains all generation/attempt/debt receipts;
- cannot publish semantic attempt outputs into a legacy run;
- cannot downgrade a semantic checkpoint in place.

---

## 26. Definition of done

This work is done only when a reviewer can select any phase, worker, or provider and answer from immutable receipts:

1. What exact semantic work was planned?
2. Why did this worker exist, and what was the full denominator?
3. What exact prompt, methodology, obligations, inputs, outputs, tools, and resources did both backends receive?
4. Which exact model and reasoning configuration executed each arm?
5. Did either arm obtain an extra child, tool, network path, retry, timeout, or validator concession?
6. Was the complete process scope closed before output trust?
7. Which attempt published, and how did PhaseIO incorporate it?
8. What debt remains?
9. Is the result structurally eligible for A/B quality comparison?
10. Can the entire claim replay without consulting mutable files or provider prose?

Until those questions have deterministic answers for all 75 SC phases, all 59 L1 phases, every model worker path, and every native provider path, Claude is the preserved legacy baseline and Codex is an operational beta—not yet a fair semantic challenger.

---

## 27. Work performed for this blueprint

- Read-only architecture and source review only.
- No repository files were edited.
- No tests were run.
- No audit was launched.
- No ground-truth data was opened or used.
- No configuration was changed.
- <PRIVATE_AUDIT_TARGET> and <PRIVATE_REGRESSION_TARGET> were not run.

