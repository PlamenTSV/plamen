# Plamen backend model-routing recommendation

**Research date:** 2026-07-29  
**Scope:** Claude and Codex model placement, reasoning effort, fallback behavior, cost control, and the driver changes needed to make those choices deterministic and auditable.  
**Change boundary:** Research and architecture recommendation only. No Plamen source, provider configuration, audit repository, or live provider session was changed or invoked.

## 1. Executive verdict

Plamen should not replace the current model names globally and call that an upgrade. The correct change is to make **semantic capability and effort a typed property of each work unit**, then map that property to an exact backend model and exact reasoning setting.

The recommended production mappings are:

| Semantic tier | Claude | Codex |
|---|---|---|
| `R3_FRONTIER_REASONING` | `claude-opus-5` | `gpt-5.6-sol` |
| `R2_STANDARD_REASONING` | `claude-sonnet-5` | `gpt-5.6-terra` |
| `R1_ECONOMY_STRUCTURED` | `claude-haiku-4-5-20251001` | `gpt-5.6-luna` |
| `N0_NATIVE_DETERMINISTIC` | no model | no model |

This is a capability mapping, not a claim that the two providers are behaviorally interchangeable. Backend parity means the same semantic work, evidence, tools, budget, and disposition authority--not identical model branding or identical output.

The effort policy should be:

- **Never use `max`.** This is a hard user constraint and should be rejected by configuration validation.
- Use `xhigh` only for narrowly identified, high-consequence work units where a measured recall or demotion-soundness gain justifies it.
- Use `high` for most Thorough discovery, depth, verification, and adjudication.
- Use `medium` for ordinary Light work and bounded synthesis/report work.
- Use `low` only for economy/schema work that cannot yet be made deterministic.

The current driver is not ready for a safe global upgrade:

1. Unknown Codex model aliases silently fall back to the Sonnet-class mapping. A future `gpt-5.6-*` value can therefore be silently demoted.
2. Codex reasoning effort is explicitly set only for `o3` and `o4-mini`; GPT-5.5/5.4 and prospective GPT-5.6 routes inherit an uncontrolled/default effort.
3. Claude launches bind `--model` but not `--effort`.
4. Driver-owned Codex depth fanout uses one phase-wide model for every role, erasing the intended role-level distinction.
5. Launch receipts and PhaseIO launch specifications bind a model name but not the reasoning setting, accepted actual model/fallback set, or refusal outcome.
6. Claude Opus 5 cybersecurity-classified requests can be rerun on Opus 4.8. Because Plamen is a security-audit workload, actual-model/fallback telemetry is a correctness requirement, not optional observability.

**Recommendation:** implement typed per-work-unit routing and receipts first, preserve `legacy_claude_v1`, then run a held-out routing A/B. Do not promote the new table to the default solely because the new models are newer. In particular, do not claim a strict Opus 5 run unless the driver can prove the actual model/fallback outcome.

## 2. Evidence and assumptions

### 2.1 Code-grounded facts

The following observations are from the current local implementation:

- `scripts/plamen_types.py:404-412` defaults both Opus settings to `claude-opus-4-8`.
- `scripts/plamen_types.py:423-455` maps Codex semantic aliases to GPT-5.5/5.4-era IDs and maps every unrecognized alias to the Sonnet-class model.
- `scripts/plamen_types.py:1543-1700` performs backend branching and Thorough promotions inside `phase_model()`. The Codex branch returns before the Claude Thorough promotion logic, so model semantics differ by backend.
- `scripts/plamen_driver.py:1734-1761` contains pre-GPT-5.6 context ceilings and defaults unknown models to 272,000 tokens.
- `scripts/plamen_driver.py:1858-1919` adds `model_reasoning_effort="high"` only for `o3` and `o4-mini`. It also hard-codes `service_tier="flex"`.
- `scripts/plamen_driver.py:11706` exposes live launch policy without a reasoning-effort field.
- `scripts/plamen_driver.py:55536` resolves one `effective_model` for the Codex depth phase and applies it across driver-owned depth jobs.
- `scripts/backend_capability_registry.py:58-66` already has the right semantic tier vocabulary and excludes `max`/`ultra` from accepted reasoning modes. This is a good substrate, but it is not yet the authoritative runtime route used by all launch paths.
- The installed local CLIs report Claude Code `2.1.220` and Codex CLI `0.145.0`. Claude exposes `--model`, `--effort`, and `--fallback-model`; Codex exposes `--model` and inline `-c key=value`, while `--ignore-user-config` suppresses user configuration.

The existing backend-parity blueprint independently identifies the same architectural requirement:

- backend-neutral typed program facts and adaptive-attention rosters must be frozen before transport;
- semantic tier must be resolved before backend mapping;
- model, context/output ceilings, reasoning mode, and capability receipt must be exact;
- silent alias, model, capacity, ChatGPT-auth, or backend fallback is prohibited within a paired generation;
- every provider path should use a WorkerTransaction and durable PhaseIO incorporation receipt.

See `Downloads/Plamen_Claude_Codex_Backend_Parity_Implementation_Blueprint_2026-07-24.md`, especially sections 4, 8, 11, 22, and 23.

### 2.2 Current official provider facts

OpenAI currently documents:

- GPT-5.6 Sol as the frontier model for complex professional work, Terra as the intelligence/cost balance, and Luna as the cost-sensitive high-volume model.
- All three provide a 1.05M context window and 128K maximum output.
- GPT-5.6 supports `none`, `low`, `medium`, `high`, `xhigh`, and `max`; OpenAI recommends preserving the old effort as a baseline and testing one level lower on representative workloads.
- Sol/Terra/Luna API prices are respectively $5/$30, $2.50/$15, and $1/$6 per million input/output tokens. Prompts above 272K input are billed at a higher rate for the entire request.

Sources: [OpenAI model guidance](https://developers.openai.com/api/docs/guides/latest-model), [GPT-5.6 Sol](https://developers.openai.com/api/docs/models/gpt-5.6-sol), [GPT-5.6 Terra](https://developers.openai.com/api/docs/models/gpt-5.6-terra), [GPT-5.6 Luna](https://developers.openai.com/api/docs/models/gpt-5.6-luna).

Anthropic currently documents:

- Claude Opus 5 for complex agentic coding, Sonnet 5 for the best speed/intelligence balance, and Haiku 4.5 for the fastest near-frontier tier.
- Opus 5 and Sonnet 5 provide 1M context and 128K maximum output; Haiku 4.5 provides 200K/64K.
- Opus 5 and Sonnet 5 use adaptive thinking and default to `high` effort on the API and Claude Code.
- Opus 5 is a drop-in model-ID upgrade from Opus 4.8 at the same API price, but thinking is on by default and effort needs a fresh workload-specific sweep.
- Opus 5 can run longer and can over-verify prompts containing old self-check instructions.
- Claude Code may rerun cybersecurity-flagged Opus 5 requests on Opus 4.8.

Sources: [Claude models overview](https://platform.claude.com/docs/en/about-claude/models/overview), [Claude migration guide](https://platform.claude.com/docs/en/about-claude/models/migration-guide), [Claude pricing](https://platform.claude.com/docs/en/about-claude/pricing), [Claude Code model configuration](https://code.claude.com/docs/en/model-config).

### 2.3 Assumptions and limits

- The user's historical "10-15% of weekly x20 allowance per Thorough audit" is the governing operational envelope. Subscription usage is not directly convertible from public per-token API pricing, so the driver must measure actual plan consumption rather than pretend to predict it from API price.
- No public model card proves Plamen recall on the user's exact corpus. The route below is an engineering hypothesis that requires the neutral held-out evaluator.
- Fable 5 is not recommended as the default R3 route. It is twice Opus 5's API price, includes additional safety/refusal considerations, and has no Plamen-specific evidence. It may be tested later as an opt-in experimental tier.
- Anthropic's invitation-only Mythos path is not assumed available and is not part of the production recommendation.

## 3. Why phase-wide model selection is the wrong abstraction

The driver's present `phase_model()` answers "which model does this phase use?" The relevant question is "what capability and effort does this **work unit** require, given its authority and risk?"

A single phase may contain:

- mechanical queue construction;
- broad candidate generation;
- a difficult cross-component security trace;
- a routine proof execution;
- a verifier about to declare a medium/high candidate safe;
- report prose with no authority to change disposition.

Those should not receive the same model merely because they share a phase label. Phase-wide promotion wastes budget on routine rows and fails to concentrate reasoning where Plamen's measured error occurs: non-application and unsound negative/demotion decisions.

Define an immutable route:

```text
ModelRouteV1
  semantic_tier
  exact_requested_model_id
  reasoning_effort
  thinking_policy
  accepted_actual_model_ids
  fallback_policy_id
  max_input_tokens
  max_output_tokens
  compaction_threshold
  tool_capability_manifest_digest
  backend_capability_receipt_digest
  route_reason_code
```

Resolve it by:

```text
pipeline + mode + phase + work_unit_role + authority + evidence risk
```

Examples of `route_reason_code`:

- `BASELINE_LIGHT_DISCOVERY`
- `THOROUGH_CORE_DEPTH`
- `TERMINAL_NEGATIVE_MEDIUM_PLUS`
- `EXTERNAL_PREMISE_UNRESOLVED`
- `SEVERITY_BOUNDARY_HIGH_IMPACT`
- `SCHEMA_ONLY_NO_JUDGMENT`

The route becomes part of `WorkPlan`, `LaunchSpec`, the arm-before-launch receipt, completion receipt, PhaseIO incorporation receipt, and RunBundle. It must be hash-stable and replayable.

## 4. Recommended model and effort policy

### 4.1 Backend mapping

| Tier | Intended authority | Claude route | Codex route | Default effort |
|---|---|---|---|---|
| R3 | Hard discovery/depth, high-stakes verification, semantic consolidation, negative adjudication | Opus 5 | GPT-5.6 Sol | `high` |
| R2 | Recon, breadth, rescan, invariant work, ordinary verification, bounded synthesis | Sonnet 5 | GPT-5.6 Terra | `medium` in Light; `high` in Core/Thorough analysis |
| R1 | Schema normalization and bounded projection that still needs a model | Haiku 4.5 | GPT-5.6 Luna | `low` |
| N0 | Parser, graph, manifest, queue, join, reconciliation, gate, projection, deterministic merge | none | none | none |

### 4.2 Mode policy

| Mode | R3 policy | R2 policy | R1/N0 policy |
|---|---|---|---|
| Light | No planned R3. Route would-be R3 work to R2 `high` and disclose the reduced assurance. | `medium`; use `high` only for terminal negative decisions that Light is authorized to make. | R1 `low`; prefer N0. |
| Core | R3 `high` for depth, high-impact verification, and terminal negative adjudication. Selective `xhigh` escalation only on typed triggers. | `high` for discovery/verification; `medium` for prose-only synthesis. | R1 `low`; prefer N0. |
| Thorough | R3 `high` as the frontier baseline. `xhigh` only for the targeted escalation set below. | `high` for reasoning work; `medium` for non-authoritative report prose. | R1 `low`; prefer N0. |

### 4.3 `xhigh` trigger set

Do not make `xhigh` a blanket Thorough setting. Escalate a work unit only when at least one of these conditions is present:

1. A verifier or skeptic is about to issue a terminal `SAFE`, `REFUTED`, `DISMISSED`, or equivalent negative disposition for a candidate whose pre-verification impact is Medium or above.
2. A demotion relies on an unresolved external premise, environmental assumption, cross-chain timing assumption, or unavailable dependency evidence.
3. A confirmed mechanism's severity crosses the Critical/High or High/Medium boundary and the harm trace remains disputed.
4. Two independent evidence channels disagree about exploitability, reachability, or material harm.
5. A core depth job has an unusually large cross-component/cross-language trace and the high-effort attempt closed with explicit unresolved obligations.
6. A found candidate would otherwise disappear from the report body despite a surviving mechanism or proof artifact.

Every escalation must preserve the same semantic obligation and create a new attempt/generation receipt; it is not invisible extra work.

This routing targets the reported error distribution directly:

- **wrongly safe/demoted half:** spend frontier effort at negative authority, require independent evidence, and forbid refusals/fallback ambiguity from becoming negative evidence;
- **methodology non-application half:** spend strong effort on obligation enumeration and missed-obligation repair, while adaptive attention routes new independent channels to uncovered obligations rather than merely increasing every phase's agent count.

## 5. Phase-family routing matrix

The matrix applies to both smart-contract and L1 registries unless noted. Exact phase names remain generated from the executable registry.

| Phase family | Recommended base tier | Light | Core | Thorough | Reason |
|---|---:|---|---|---|---|
| Bake, parser, graph construction | N0 | native | native | native | Mechanically derived facts must not vary by model. |
| Recon | R2, except difficult L1 architecture escalation R3 | Terra/Sonnet `medium` | Terra/Sonnet `high`; L1 cross-subsystem lead may be Sol/Opus `high` | Terra/Sonnet `high`; R3 only for difficult architecture synthesis | Parallel complete-source recon values coverage; blanket Opus is not proven necessary. |
| Instantiate | R2 | `medium` | `high` | `high` | Security-obligation instantiation is reasoning-heavy but usually bounded by recon facts. |
| Breadth | R2 base, selective R3 | `medium` | `high` | `high`; R3 for high-risk seam/obligation shards | Use more independent semantic channels only when the frozen attention roster calls for them. |
| Rescan/per-contract | R2 | `medium` | mode-gated | `high` | These exist to counter non-application and sibling/variant misses; economy routing would defeat their purpose. |
| Prepare/planner manifests | N0 target; R1 transitional | Luna/Haiku `low` if needed | same | same | Roster construction should be deterministic once inputs are typed. |
| Inventory chunks | R2 | `medium` | `high` | `high` | Chunks need semantic consolidation without report authority. |
| Inventory final merge | R3 | R2 `high` with Light debt | Sol/Opus `high` | Sol/Opus `high` | Found-then-lost risk is concentrated at consolidation. Mechanical identity reconciliation remains authoritative. |
| Semantic invariants pass 1/2 | R2 | mode-gated | `high` | `high`; R3 only for disputed global invariants | Strong reasoning matters; blanket frontier is not yet justified. |
| Core depth roles | R3 | R2 `high` | Sol/Opus `high` | Sol/Opus `high`, selective `xhigh` | Highest discovery value and cross-function reasoning burden. |
| Niche depth roles | R2 base, R3 by trigger | R2 `medium` if enabled | R2 `high` | R2 `high`; R3 when flag severity/scope warrants | Avoid paying frontier price for every niche prompt. |
| Attention repair / enumgap / axis coverage | R2 | mode-gated | `high` | `high` | Directly repairs methodology non-application; typed obligations should select the channel. |
| Exploration/application skeptic | R3 for negative authority | R2 `high` if enabled | Sol/Opus `high` | Sol/Opus `high`; `xhigh` on terminal-negative triggers | The pipeline's false-safe error demands stronger negative-side scrutiny. |
| Semantic dedup | R3 for root-cause identity; N0 reconciliation | R2 `high` with Light debt | Sol/Opus `high` | Sol/Opus `high` | Dedup can cause silent finding loss; model suggests groups, mechanical ledger preserves every member. |
| RAG/precedent sweep | R2 | skipped | `high` | `high` | Precedent can challenge assumptions but must not control disposition. |
| Chain/composition | R3 | R2 `high` with Light debt | Sol/Opus `high` | Sol/Opus `high`; selective `xhigh` for disputed multi-hop chains | Cross-component composition is structurally hard and often under-served by local passes. |
| Verify queue/roster | N0 | native | native | native | Exact candidate denominator and shard assignment are deterministic. |
| Critical/high verification | R3 | R2 `high` with Light assurance limit | Sol/Opus `high`; `xhigh` on negative trigger | Sol/Opus `high`; `xhigh` on negative trigger | A negative has higher recall risk than a positive; effort follows disposition authority. |
| Medium verification | R2 positive path; R3 negative escalation | Terra/Sonnet `high` | Terra/Sonnet `high`, escalate negative | Terra/Sonnet `high`, escalate negative | Concentrates frontier spend on unsafe demotions rather than every proof run. |
| Low verification | R2 in Thorough | mode-defined | mode-defined | Terra/Sonnet `high`, R3 only on systemic/high-impact reclassification | Thorough verifies all severities, but ordinary low rows do not need blanket frontier spend. |
| Verify aggregate | N0 | native | native | native | Aggregate exact receipts and outcomes without model interpretation. |
| Mechanical verify / post-extract / promotion harvest | N0 | native | native | native | These are deterministic integrity controls. |
| Skeptic-judge | R3 | R2 `high` with Light debt | Sol/Opus `high` | Sol/Opus `high`; selective `xhigh` | Independent disposition challenge is high-authority work. |
| Cross-batch reconciliation | N0 identity join + R2 semantic review | R2 `medium` | R2 `high` | R2 `high` | Mechanically reconcile identity; model judges only genuine semantic conflicts. |
| Severity adjudication shadow | R3 | mode-gated | Sol/Opus `high` | Sol/Opus `high`; `xhigh` at material boundaries | Directly addresses depth-side under-rating without granting silent report authority. |
| Report index | R3 semantic plan + N0 completeness gate | R2 `high` with Light debt | Sol/Opus `high` | Sol/Opus `high` | Report placement is a known found-then-lost point. |
| Report body writers | R2 | `medium` | `medium` | `medium` or `high` for Critical/High prose only | Verified identity/severity is already fixed; frontier prose everywhere is poor ROI. |
| Tier projection/merge | N0 target; R1 transitional | Luna/Haiku `low` if needed | same | same | Projection should not make security judgments. |
| Report assemble | N0 target; R1 transitional | R1 `low` | R1 `low` | R1 `low` | Assembly should be deterministic over fixed sections. |
| Report dedup | N0 ledger + R3 only for disputed root-cause grouping | N0/R2 | N0/R3 by dispute | N0/R3 by dispute | Model may propose clusters; it must never delete members or override the ledger. |
| Report disposition | R3 for ambiguity; N0 for policy application | R2 `high` with Light debt | Sol/Opus `high` for ambiguous rows | Sol/Opus `high`; `xhigh` on terminal-negative trigger | This is the last high-risk loss boundary. |
| Report floor | N0 | native | native | native | The floor is policy, not prose judgment. |

### Important correction to the current depth path

The four core depth roles are not interchangeable. The route must be attached to each compiled depth job, not to `phase="depth"`:

- token-flow and cross-function state-trace normally start R3;
- external/timing and edge-case work may start R2 or R3 depending on the frozen obligation and impact;
- niche roles start R2 unless a typed risk trigger promotes them;
- a role that is about to close a serious obligation negatively may receive an R3/xhigh adjudication attempt even if its discovery attempt used R2.

This is an example of spending more where it can affect recall while avoiding a phase-wide brute-force multiplier.

## 6. Claude 5 migration safety

### 6.1 Recommended default

Use `claude-opus-5` as the candidate R3 model and `claude-sonnet-5` as R2, but keep `legacy_claude_v1` frozen on its exact prior model and arguments.

Opus 5 has the same published API token price as Opus 4.8, so the main cost risk is not the nominal rate. It is:

- adaptive thinking being on by default;
- recalibrated effort behavior;
- longer visible deliverables;
- possible over-verification from old prompts;
- fallback/retry amplification in cybersecurity work;
- increased agent delegation if prompts leave orchestration open-ended.

Therefore:

1. Always pass `--effort` explicitly.
2. Keep thinking enabled for xhigh; do not combine xhigh with disabled thinking.
3. Remove only redundant model-self-check prose after prompt-level A/B testing. Do not remove Plamen's independent verifier, skeptic, or mechanical gates; those are architectural discriminator separation, not redundant self-prompting.
4. Keep subagent creation driver-owned and capped. A model worker must not expand the roster.
5. Put explicit output schemas/length budgets on report and structured phases.

### 6.2 Cybersecurity fallback is a correctness boundary

Official Claude Code documentation states that cybersecurity-flagged Opus 5 requests can rerun on Opus 4.8. That means:

- requested model is not enough;
- a completion receipt must record the actual model or an explicit provider fallback event;
- refusal or unobservable fallback can never be interpreted as evidence that a candidate is safe;
- strict paired evaluation excludes attempts whose actual route cannot be proven;
- operational mode may accept a declared route set `{claude-opus-5, claude-opus-4-8-on-cyber-fallback}` only if that policy is explicit before launch and the event is observable.

If the current Claude stream cannot prove actual model/fallback, keep security-critical R3 production work on Opus 4.8 while Opus 5 runs in shadow/canary mode. This is not a capability judgment; it is an evidence-integrity requirement.

Do not set a global fallback that silently changes semantic tier. Capacity/unavailability fallback must become typed debt or a new authorized execution generation.

## 7. Codex 5.6 migration safety

### 7.1 Recommended default

Use:

- `gpt-5.6-sol` for R3;
- `gpt-5.6-terra` for R2;
- `gpt-5.6-luna` for R1.

Do not use the unsuffixed `gpt-5.6` alias in benchmark or receipt-critical mode even though it currently resolves to Sol. Exact IDs make route intent legible and reduce future alias drift.

### 7.2 Required command behavior

Because the driver launches Codex with `--ignore-user-config`, every launch must carry:

```text
--model <exact-model-id>
-c model_reasoning_effort="<low|medium|high|xhigh>"
```

The current special case for only `o3`/`o4-mini` must be retired under `semantic_v1`.

Unknown model IDs or aliases must fail closed. Specifically, `_resolve_codex_model_alias()` must not return the Sonnet mapping for an unrecognized value.

The ChatGPT-auth recovery path that retries without `--model` cannot count as the same generation. It either:

- retries the exact requested model;
- creates explicit model-unavailable debt; or
- starts a new user-authorized generation with a new route receipt.

### 7.3 Context and cost policy

Update GPT-5.6 context metadata to 1,050,000 input tokens and 128,000 output tokens, but do not automatically feed every worker a million-token bundle.

Use two explicit context classes:

- `ROUTINE_CAPPED`: keep input below the current 220K-ish compaction/cost boundary for ordinary R1/R2 work;
- `LARGE_CONTEXT_AUTHORIZED`: allow a larger source bundle for complete-source R3 work when the work plan records why it is needed.

The 272K API pricing boundary should be visible in the route and cost receipt. Crossing it may still be the right recall decision, but it should never happen accidentally because the advertised context window grew.

## 8. Exact implementation changes

### 8.1 One routing authority

Create or extend a single module, preferably `scripts/backend_capability_registry.py`, to own:

- semantic tier definitions;
- backend exact-model mappings;
- supported effort levels;
- per-mode/per-work-unit route rules;
- context/output ceilings;
- accepted fallback policy;
- validation that forbids `max`;
- route serialization and digest.

`phase_model()` should become a legacy adapter only. Production `semantic_v1` launches receive a `ModelRouteV1`, never a bare model string.

### 8.2 Schemas and receipts

Extend:

- `PhaseIOContract.LaunchSpec`;
- WorkPlan/worker transaction launch plan;
- arm receipt;
- completion/debt receipt;
- PhaseIO incorporation receipt;
- RunBundle manifest.

Required fields:

```text
semantic_tier
requested_model_id
reasoning_effort
thinking_policy
accepted_actual_model_ids
fallback_policy_id
actual_model_id
fallback_event
refusal_stop_reason
provider_account_mode
max_input_tokens
max_output_tokens
observed_input/cached/output/reasoning tokens
route_reason_code
route_digest
capability_receipt_digest
```

If `actual_model_id` is not observable, record `UNKNOWN_BLOCKED`; do not invent it from the command line.

### 8.3 Launchers

All launch paths--Claude PTY, Claude headless, Codex exec, recon pools, breadth pools, rescan, depth fanout, dynamic verifiers, chain tail, resume, and missing-only recovery--must consume the same route.

Claude:

```text
claude --model <exact-id> --effort <exact-level> ...
```

Codex:

```text
codex exec --model <exact-id> -c model_reasoning_effort="<exact-level>" ...
```

The locally installed CLIs support these controls. Preflight must still test the exact configured route and reject unsupported options before launching audit workers.

### 8.4 Prompt/runtime consistency

Prompts and generated role descriptions must not claim "Sonnet," "Opus," or a Codex model directly. Render a non-authoritative runtime note from the resolved route receipt when useful.

Model-specific prompt tuning belongs in a versioned transport overlay. It must not alter:

- methodology obligations;
- source/evidence bundle;
- candidate/disposition schema;
- tool authority;
- output denominator;
- verification or report gates.

This prevents a Claude 5 prompt cleanup from silently changing the methodology.

### 8.5 Refusal and fallback semantics

Add terminal attempt states:

- `MODEL_REFUSAL`
- `MODEL_FALLBACK_OBSERVED`
- `MODEL_FALLBACK_UNOBSERVABLE`
- `MODEL_UNAVAILABLE`
- `REASONING_CONTROL_UNMATCHED`

None is a negative security disposition. They produce retry/debt according to the frozen attempt policy. A candidate remains unresolved and report-visible where policy requires.

## 9. Cost and agent-count policy

Increasing agent count phase-wide is not the preferred response to attention failures. It can increase correlated duplicates, report bloat, and weekly use without adding independent reasoning.

Use this order:

1. Freeze a complete obligation denominator.
2. Assign semantically distinct channels/seams.
3. Detect uncovered, disputed, or weakly evidenced obligations.
4. Add a new independent channel only for that gap.
5. Escalate model/effort only when the work unit's authority and risk justify it.

For the user's x20 Thorough envelope:

- target the historical 10-15% weekly usage as the non-inferiority budget;
- preserve the old route as a measured control;
- let xhigh consume no more than a predeclared share of reserved attention units;
- keep report prose on R2 instead of blanket R3;
- prefer N0 for queues, joins, projections, assembly, and gates;
- use cacheable stable methodology/source prefixes where provider semantics allow it;
- record plan percentage or provider usage telemetry when available, but never infer it from dollar pricing.

Suggested initial ceiling for the new route experiment:

- no more total reserved attention units than the legacy Thorough arm;
- at most 10% of model work units eligible for xhigh;
- xhigh only through the typed trigger set;
- any audit exceeding 15% weekly usage without a measured recall gain fails the operational cost gate;
- a material Critical/High recall gain may justify an explicitly approved higher envelope, but not silently.

These numbers are launch hypotheses, not validated constants. Tune them on the held-out corpus, not on <PRIVATE_REGRESSION_TARGET> or another motivating case.

## 10. Verification and rollout plan

### Stage 0 -- freeze legacy behavior

- Snapshot exact Claude 4.8 and current Codex routes, argv, effort/default behavior, prompts, manifests, and receipts.
- Keep `legacy_claude_v1` byte/semantic compatible.
- Add a route-dry-run command that emits every resolved work-unit route without invoking a provider.

### Stage 1 -- schema and fail-closed fixtures

Red-to-green fixtures must prove:

1. unknown Codex model IDs fail rather than map to R2;
2. `max` is rejected for both backends;
3. every model launch contains explicit effort;
4. N0 work never launches a model;
5. every depth role can receive its own route;
6. route digest changes if model, effort, fallback policy, or context budget changes;
7. ChatGPT-auth model rejection cannot retry without an exact model inside the same generation;
8. Claude refusal/fallback cannot become `SAFE`/`REFUTED`;
9. actual-model unknown becomes typed debt;
10. resume rejects a mismatched route digest;
11. report-only workers cannot change verified disposition/severity;
12. legacy profile argv and model choices are unchanged.

### Stage 2 -- provider contract canaries

Use non-audit canaries to verify:

- each exact model is available;
- each effort value is accepted;
- context/output metadata agrees with the provider;
- model, usage, refusal, and fallback events can be parsed;
- PTY/headless/Codex receipts preserve the same fields;
- unsupported capability closes as debt without a false completion marker.

Do not use provider success alone as a security-quality result.

### Stage 3 -- paired routing A/B

Hold constant:

- code snapshot;
- methodology and semantic prompt digests;
- typed program facts;
- adaptive-attention roster;
- tools/native commands;
- per-work-unit token and time ceilings;
- seeds/nonces where controllable;
- report and verification schemas.

Compare:

- legacy route;
- new models at the same effective effort baseline;
- new models one effort level lower where official migration guidance recommends testing it;
- targeted xhigh escalation versus no escalation.

Measure separately:

- strict ground-truth root-cause recall;
- never-found misses;
- found-then-lost misses;
- unsupported negative/demotion count;
- methodology-obligation application coverage;
- precision and duplicate/root-cause fragmentation;
- severity accuracy;
- proof execution honesty;
- report identity retention;
- tokens, retries, wall time, fallback/refusal rate;
- weekly-plan usage percentage for Claude.

Acceptance:

- zero found-then-lost regression;
- zero unauthorized negative closure;
- zero silent model/effort/fallback drift;
- no Critical/High recall loss on held-out cases;
- aggregate recall non-inferior, with the predeclared confidence interval from the existing evaluator design;
- precision and severity accuracy non-inferior within a predeclared margin;
- normal Thorough Claude use remains close to 10-15% weekly unless a measured recall gain justifies and the user approves a larger envelope.

<PRIVATE_REGRESSION_TARGET> and any motivating audit remain regression fixtures only, never scored evidence for the route.

### Stage 4 -- gradual cutover

1. Land routing/receipt infrastructure with legacy behavior.
2. Shadow-route new models without changing disposition authority.
3. Enable new R1/R2 routes first after non-inferiority.
4. Enable R3 `high`.
5. Enable typed xhigh escalation last.
6. Preserve a one-command legacy rollback until multiple ecosystem/OS canaries and held-out audits pass.

## 11. Final engineering judgment

The new models are worthy of building out and testing, but the high-leverage change is **not** "Opus 5 everywhere" or "Sol everywhere." It is the route/receipt architecture that makes capability spend deliberate and makes model-driven false-safe decisions auditable.

The recommended routing directly addresses the two reported failure modes:

- stronger and explicitly independent obligation coverage for non-application misses;
- frontier/xhigh escalation at the negative-disposition boundary for wrongly safe or demoted findings.

It also avoids the main bloat failure:

- deterministic work stays N0;
- report prose stays mostly R2;
- niche work starts R2;
- xhigh is conditional rather than phase-wide;
- extra agents require an uncovered semantic obligation rather than a raw count heuristic.

Confidence is high that these changes close the **architectural mechanisms** that currently permit silent effort drift, model drift, phase-wide under/over-spend, and refusal/fallback-induced false negatives. It would be unsound to promise a numeric recall increase before held-out paired audits. The correct release claim is: **the design is fit to implement behind `semantic_v1`, and it should become the default only after the neutral evaluator proves recall non-inferiority and the targeted escalation proves value within the user's cost envelope.**
