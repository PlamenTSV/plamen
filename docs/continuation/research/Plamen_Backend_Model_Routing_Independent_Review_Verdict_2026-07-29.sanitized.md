# Plamen Backend Model Routing Recommendation

## Independent Blocking Review Verdict

Date: 2026-07-29

Verdict: BLOCK AS AN EXECUTABLE ROLLOUT GUIDE

Architecture direction: PASS WITH REQUIRED CORRECTIONS

The recommendation is directionally strong: capability and effort belong to a
typed work unit, not to a phase-wide nickname; deterministic work should stay
model-free; negative disposition deserves more reasoning authority than routine
positive synthesis; fallback, refusal, and actual-provider behavior are evidence
integrity concerns; and the legacy Claude path should remain frozen until a
neutral held-out evaluation clears a cutover.

It is not yet safe to implement literally or accept for production rollout.
Seven corrections below are required before implementation acceptance. The
largest are a false Claude Haiku effort assumption, incomplete proof of
post-init Claude model transitions, an incomplete effort-authority boundary, and
an unsafe Light-mode negative-disposition rule.

No provider was invoked. No audit was launched. No repository or source artifact
was edited by this review. Local CLI help and versions were inspected read-only.

## 1. Review boundary

Reviewed recommendation:

- Path:
  `<LOCAL_USER_ROOT>\Downloads\Plamen_Backend_Model_Routing_Recommendation_2026-07-29.md`
- SHA-256:
  `4167D7976F2EA1735C68CC3EBF78CB0FEB4BF012F1DE86F0077A9A6E3E4B547E`

Reviewed implementation tree:

- Repository:
  `<LOCAL_USER_ROOT>\plamen-codex-implementation`
- Branch:
  `codex/recall-app-benchmark-r10_1`
- HEAD:
  `67a0f85adc7a8169d79a286908b00bef7adb764a`
- Worktree:
  dirty and shared; this review is bound to the file hashes below, not to HEAD
  alone.

Relevant source hashes:

| File | SHA-256 |
| --- | --- |
| `scripts/plamen_types.py` | `74D540E7B5A8C05D2746D1058A712F1A3B088614F856B1D1AA8F6590B847F4EF` |
| `scripts/plamen_driver.py` | `00D30B844719FFEE31C0DBE1070A1D2E8C1BF8E3ABCF00EAFC20109D9B83A6B4` |
| `scripts/backend_capability_registry.py` | `897FA92B03DD3EE7A6031D3C61E073139511ACE04655172F1FFDCE26A5DEE4A6` |
| `scripts/phase_io_contracts.py` | `C361C2545709DF3F0000715F77BA40A7F76FD7B6C7CBB90A1AF0374676163062` |
| `scripts/worker_transaction.py` | `47773F533A5E133626F4C3FB580AF1FC53FC931832EAB7BF07393C4508B52C35` |
| `scripts/claude_provider_policy.py` | `95DAFA363ACA0C587E400CC31D9414A045064E33F4D8184E43D435BEB22BFED9` |
| `scripts/claude_headless_profile.py` | `EF0BF3FDFAE3108B51255D3735E7D7388ED263EC1D56CD352AC47C9B192B3A01` |
| `scripts/claude_provider_preparation.py` | `B570EB8507EE28B4433E79B2EB751DD096CC599CB9CAFE42AD87C8B22FA94BC3` |
| `scripts/claude_stream_json_evidence.py` | `8FDE700037D43C874EACCB77A16F47BFEE46D79C88D8CFBB2B9421F56F949BBD` |
| `scripts/semantic_work_plan.py` | `D3A89ACCE8A7F0275112E964A1CD40A7D49E68474F02637A64CBF4C8AA10FF67` |
| `scripts/worker_execution_receipts.py` | `A2CB4A190BFA453902E053670EC97FE937D19F5C33B7203FBE4FFC0DDAD7309B` |

Observed local clients:

- Claude Code: `2.1.220`
- Codex CLI: `0.145.0`
- Claude help exposes `--model`, `--effort`, and `--fallback-model`.
- Codex `exec` help exposes `--model`, `-c/--config`, and
  `--ignore-user-config`.

These observations prove local flag availability only. They do not prove model
entitlement, provider acceptance, actual routed model, effective effort, cost,
or audit quality.

## 2. Claims that are supported

### 2.1 Current code problems are real

The recommendation correctly identifies the following code-grounded defects:

1. `plamen_types.py` has a closed pre-5.6 Codex model table and silently maps an
   unknown alias to the Sonnet-class default. A future or misspelled exact model
   can therefore be silently demoted.
2. `phase_model()` is phase-wide. Depth fanout resolves one effective model
   before its role loop, so materially different work units inherit one route.
3. The current Codex command explicitly sets reasoning effort only for selected
   older reasoning models. It does not bind effort for the proposed GPT-5.6
   routes.
4. The current Claude provider command binds `--model` but not `--effort`.
5. PhaseIO, worker-plan, and execution-receipt boundaries do not carry the full
   proposed route denominator.
6. The Codex path can retry without an explicit model or mutate the selected
   model after rejection/unavailability. That is incompatible with a strict
   paired generation unless the change becomes a new typed generation.
7. The existing semantic capability registry is useful substrate, but it is not
   yet the production launch authority for model-backed semantic work.
8. `semantic_v1` and `legacy_claude_v1` identities now exist in the semantic
   work-plan substrate, but that does not itself prove a frozen legacy launch
   profile or a complete semantic provider cutover.

### 2.2 Current model names and public API facts are mostly correct

Official current documentation supports:

- `gpt-5.6-sol`, `gpt-5.6-terra`, and `gpt-5.6-luna` as current model IDs.
- The unsuffixed `gpt-5.6` alias currently routes to Sol.
- Each GPT-5.6 family page advertises a 1,050,000-token context window and
  128,000 maximum output.
- Public standard API rates of $5/$30 for Sol, $2.50/$15 for Terra, and $1/$6
  for Luna per million input/output tokens.
- The higher-price rule for requests above 272K input.
- `claude-opus-5`, `claude-sonnet-5`, and
  `claude-haiku-4-5-20251001` as current model IDs.
- Opus 5 and Sonnet 5 at 1M context and 128K maximum output; Haiku 4.5 at
  200K/64K.
- Public standard API rates of $5/$25 for Opus 5, $3/$15 for Sonnet 5, and
  $1/$5 for Haiku 4.5. Sonnet 5 introductory pricing is $2/$10 through
  2026-08-31.
- Opus 5 requires Claude Code 2.1.219 or later; the observed local 2.1.220
  satisfies that client-version minimum.

The capability-tier mapping is a reasonable policy hypothesis:

- R3: Opus 5 or GPT-5.6 Sol
- R2: Sonnet 5 or GPT-5.6 Terra
- R1: Haiku 4.5 or GPT-5.6 Luna
- N0: no model

It is not evidence that paired models are behaviorally equivalent. The tier is
a Plamen authority class, not a provider-neutral quality guarantee. Each
backend still needs a separate held-out result.

### 2.3 The phase placement is directionally sound

The recommendation appropriately concentrates R3 reasoning on:

- hard depth and cross-component traces;
- independent negative adjudication;
- critical/high verification;
- root-cause identity disputes;
- inventory and report loss boundaries;
- severity-boundary disputes.

It also correctly keeps queues, exact joins, manifests, receipts,
reconciliation, policy gates, and identity-preserving projection in N0 when
their inputs and semantics are fully typed.

Model-generated root-cause grouping, severity judgment, conflict resolution,
and incomplete-schema interpretation are not N0 merely because Python invokes
them. They remain semantic work and must retain model evidence plus a
recall-safe mechanical denominator.

## 3. Blocking corrections

### B1. Haiku 4.5 cannot implement the proposed R1 effort contract

Severity: BLOCK

The recommendation assigns Haiku 4.5 an R1 default of `low` and later requires
every launch to contain explicit effort. Official Anthropic migration guidance
states that effort is not available on Claude Haiku 4.5.

Required correction:

- Encode Haiku 4.5 reasoning as `not_applicable`, not `low`.
- Do not emit `--effort` for a Haiku 4.5 route.
- If explicit `low` effort is a semantic requirement, route that work to
  Sonnet 5 `low` or keep it N0; do not assert a fictional Haiku effort.
- Capability fixtures must reject model/effort combinations that the provider
  does not support.

This is a concrete example of why a semantic capability tier must not be
implemented as identical argument spelling across providers.

### B2. An accepted-model set and one actual-model scalar are insufficient

Severity: BLOCK

Claude Code distinguishes:

1. availability fallback chains, which can switch for the current turn; and
2. content-classifier fallback, where an Opus 5 cybersecurity-flagged request
   can be rerun on Opus 4.8 and the session can continue on the fallback model.

The current stream validator checks `init.model` against `accepted_models`.
For assistant events, it only requires `assistant.message.model` to be a
non-empty string. It does not compare every assistant model to the accepted
route. It only checks that `result.modelUsage` is an object, does not validate
its model keys, and does not retain model sequence or usage in the normalized
summary.

Therefore a valid Opus 5 init followed by a post-init Opus 4.8 transition can
evade the current init-only proof. A predeclared set
`{claude-opus-5, claude-opus-4-8}` can also hide mixed-model evidence.

Required correction:

- Represent availability fallback and content-classifier fallback as separate
  policies.
- Persist the ordered requested and observed model sequence for every root and
  subagent assistant event, plus all `modelUsage` keys and transition notices.
- Validate every observed model against an ordered transition policy, not an
  unordered accepted set.
- In a strict benchmark arm, any model transition or unobservable transition
  terminates that attempt as typed debt and excludes it from paired scoring.
- In operational mode, a model change must end the current semantic attempt and
  start a new authorized execution generation. Mixed-model evidence must not
  certify one strict attempt.
- A refusal, classifier flag, blocked fallback, or unobservable actual model
  may never produce `SAFE`, `REFUTED`, `DISMISSED`, or equivalent negative
  evidence.

Sonnet 5 also has real-time cybersecurity safeguards and can return refusal as
a successful HTTP response. The same refusal terminal-state rules must cover
R2 Sonnet routes, not only Opus fallback.

### B3. Passing `--effort` is not proof of effective effort

Severity: BLOCK

The recommendation says to always pass Claude `--effort`. Official Claude Code
documentation also exposes `CLAUDE_CODE_EFFORT_LEVEL`, which can override
session effort. Organization policy and model capability can further constrain
what is effective.

Required correction:

- Scrub or fail closed on `CLAUDE_CODE_EFFORT_LEVEL` at the sealed Claude
  launch boundary.
- Bind the sanitized environment digest and forbidden effort-related settings.
- Record `requested_effort`, `provider_supported_effort`, and
  `observed_effective_effort` separately.
- If effective effort is not observable, record
  `EFFECTIVE_EFFORT_UNOBSERVABLE`; do not relabel requested effort as actual
  effort.
- Codex must continue using `--ignore-user-config` and an explicit
  `model_reasoning_effort`, with the same requested-versus-observed
  distinction.
- Reject `max`, `ultracode`, provider-default, and unknown effort at every
  semantic entry point. The user-approved ceiling is `xhigh`.

### B4. Context window is mislabeled as maximum input

Severity: BLOCK FOR SCHEMA, NON-BLOCKING FOR THE POLICY IDEA

The recommendation correctly quotes a 1,050,000-token GPT-5.6 context window
and 128,000 maximum output. It later instructs the implementation to set
"1,050,000 input tokens." The cited public page labels 1,050,000 as the
context window, not as an independently proven maximum-input field.

Required correction:

- Store `context_window_tokens=1050000`.
- Store `max_output_tokens=128000`.
- Do not populate `max_input_tokens=1050000` from that citation.
- Derive an operational prompt/input ceiling separately from provider
  capability, reserved output/reasoning headroom, tool expansion, and Plamen's
  own bundle budget.
- A large advertised window must not silently authorize a million-token work
  bundle.

### B5. Light mode may not convert an R3 negative into an R2 terminal negative

Severity: BLOCK

The recommendation says Light has no planned R3 and routes would-be R3 work to
R2 `high`, including terminal negatives Light is authorized to make. That is
not recall-safe for a pipeline whose dominant judgment error is false safety.
Reduced-assurance disclosure does not repair a dropped candidate.

Required correction:

- Light may use R2 `high` for discovery and provisional analysis.
- Light may not issue a terminal negative for a material candidate that the
  route policy classifies as R3-authority work.
- Such a candidate must remain `UNRESOLVED/NEEDS_R3_REVIEW`, remain visible,
  and be re-queued or disclosed without demotion.
- If the product requires a terminal material negative in Light, it must pay
  for the R3 adjudication despite the mode.

The xhigh triggers also rely partly on mutable pre-verification severity.
Because under-rating is itself an observed recall failure, escalation cannot
depend only on a previously assigned Medium/High label. It must also trigger
from objective risk facts such as confirmed mechanism, material asset/control
reach, disputed harm trace, external premise, severity disagreement, surviving
proof artifact, or unresolved negative obligation.

### B6. The route and receipt denominator is incomplete

Severity: BLOCK

The proposed fields are a good start, but deterministic replay also needs:

- route schema version;
- exact provider transport and account/auth mode;
- minimum and observed provider CLI version;
- requested service tier and observed service tier;
- separate availability-fallback and classifier-fallback policies;
- ordered actual model sequence, not one model field;
- requested, supported, and observed effort states;
- thinking/adaptive-thinking mode where applicable;
- refusal/classifier terminal category;
- generation and attempt identity;
- prompt, tool policy, source/program-facts, context-budget, and route digests;
- disposition authority and negative-closure risk;
- provider capability-manifest version.

The current Codex builder hard-codes `service_tier="flex"`. OpenAI documents
that the response's actual service tier can differ from the requested tier.
Service tier must therefore be route-bound and receipt-observed, not left as
an unrelated hard-coded launch detail.

Opus 5 also lacks web fetch and Priority Tier relative to Opus 4.8. If any
Plamen work unit depends on those provider features, the capability manifest
must reject that route or supply an explicit tool-level substitute. A model
name upgrade is not a complete capability upgrade.

### B7. The cost gate uses an unsafe denominator

Severity: BLOCK FOR A CLAIMED COST GUARANTEE

"At most 10% of model work units eligible for xhigh" is not a reliable budget.
One large depth job can consume more resources than many bounded jobs. Public
API token prices also do not predict Claude x20 subscription allowance or
Codex/ChatGPT entitlement consumption.

Required correction:

- Budget xhigh by predeclared weighted resource grants: prompt/input budget,
  output budget, turns, retries, wall-time ceiling, and model price/plan class.
- Report raw work-unit count only as secondary telemetry.
- Separate API-priced runs from subscription/entitlement runs.
- Treat the user's historical 10-15% weekly Claude consumption as an observed
  operational target, not a deterministic conversion from API prices.
- If the client cannot attribute weekly plan consumption to one audit, report
  `PLAN_CONSUMPTION_UNOBSERVABLE`; do not claim that the 15% gate passed.
- Require recall or demotion-soundness gain plus user approval before widening
  the historical envelope.

## 4. Required wording and design refinements

These do not reject the architecture, but they prevent overclaiming:

1. Exact model strings reduce alias drift. They do not by themselves prove an
   immutable provider snapshot across dates. Bind the provider response,
   capability-manifest version, CLI version, and evaluation date.
2. Opus/Sol, Sonnet/Terra, and Haiku/Luna are role mappings, not capability
   equivalence claims.
3. Opus 5's same public API price as Opus 4.8 does not imply equal x20 plan
   consumption, latency, turns, or output volume.
4. Fable 5 is officially Anthropic's most capable widely released model, not
   merely an unclear future option. Excluding it from default routing is still
   reasonable because it costs $10/$50 per million tokens and has no
   Plamen-specific held-out evidence. A small opt-in canary may test it later.
5. The report-body and inventory routing changes are deliberate experiments,
   not behavior-preserving refactors. Current Thorough routing promotes more
   report work to Opus-class models. Moving prose to R2 and assembly toward N0
   is sensible, but must clear report-quality and completeness A/B gates.

## 5. Corrected route policy

The following is acceptable as an implementation target:

| Authority class | Claude candidate | Codex candidate | Reasoning |
| --- | --- | --- | --- |
| R3 | `claude-opus-5` | `gpt-5.6-sol` | `high`; typed `xhigh` only |
| R2 | `claude-sonnet-5` | `gpt-5.6-terra` | `medium` or `high` |
| R1 | `claude-haiku-4-5-20251001` | `gpt-5.6-luna` | Claude `not_applicable`; Codex `low` |
| N0 | none | none | not applicable |

Global invariants:

1. `max`, `ultracode`, and any level above `xhigh` are rejected.
2. Unknown model, effort, feature, service-tier, or alias input becomes typed
   debt; it never falls through to a cheaper or provider-default route.
3. A model change requires a new execution generation.
4. A retry within one generation preserves prompt snapshot, tools, model,
   reasoning contract, source denominator, and route digest.
5. N0 launches no provider.
6. Negative evidence requires an eligible completion with no refusal, no
   unaccepted model transition, no applicability mismatch, and the required
   independent authority.
7. Legacy Claude stays default and frozen until neutral held-out evaluation
   clears the candidate route.

Recommended mode correction:

- Light: R2 discovery and provisional judgment; no terminal material R3
  negative without escalation.
- Core: R3 high at depth, material verification, semantic consolidation, and
  terminal negative boundaries; typed xhigh only.
- Thorough: R3 high baseline for the same high-authority work; xhigh only on
  objective risk and unresolved-negative triggers.

## 6. Acceptance tests required before implementation approval

### 6.1 Pure route matrix

Enumerate every:

- ecosystem;
- SC/L1 pipeline;
- phase, subphase, and role;
- Light/Core/Thorough mode;
- positive, negative, disputed, and unresolved authority state;
- model capability tier;
- provider;
- effort capability;
- fallback/refusal state;
- service tier and account mode.

Assert one exact route or one explicit debt. Assert there is no default branch.

### 6.2 Claude fixtures

Required red-to-green cases:

- Haiku plus `low` is rejected or normalized to `not_applicable`; no
  `--effort` is emitted.
- Opus and Sonnet receive only provider-supported explicit effort.
- `CLAUDE_CODE_EFFORT_LEVEL` cannot override the sealed route.
- init model accepted but later assistant model changed: strict attempt fails.
- `modelUsage` contains an unaccepted model: strict attempt fails.
- availability fallback and classifier fallback are distinguished.
- Opus 5 to Opus 4.8 transition creates a new generation or typed debt.
- Sonnet 5 `stop_reason=refusal` cannot certify a negative.
- content refusal returned in a successful transport envelope remains adverse.
- unsupported CLI version, missing actual-model evidence, or missing effort
  evidence cannot silently pass.

### 6.3 Codex fixtures

Required red-to-green cases:

- unknown/future aliases fail closed;
- exact Sol/Terra/Luna model and exact effort appear in the sealed command;
- `--ignore-user-config` is present;
- no ChatGPT-auth retry removes the exact model within the same generation;
- capacity/model fallback creates debt or a new generation;
- requested and observed service tier are retained;
- actual model unobservable excludes a strict paired arm;
- `max` and all above-xhigh aliases are rejected.

### 6.4 Lifecycle and compatibility

- Legacy Claude argv, prompt, tool policy, route, and receipts remain
  hash/semantic compatible.
- New route fields survive PhaseIO, worker plan, runtime materialization,
  execution receipts, RunBundle v2, resume, repair, and reconciliation.
- R10 joins and all finding identity joins remain unchanged by route metadata.
- N0 never launches a model on Windows, Linux, or macOS.
- Unsupported provider feature or version degrades to a loud review item,
  not a false completed phase and not a halt.

### 6.5 Held-out evaluation

Run no cutover from same-repository fixtures alone. The neutral evaluator must
compare legacy and candidate arms on governed held-out corpora with:

- identical source snapshot and prompt/work roster;
- distinct execution generation per backend/model route;
- no silent fallback;
- actual route evidence;
- exact candidate denominator;
- recall split into never-found and found-then-lost;
- false-safe/demotion rate;
- precision, root-cause fragmentation, severity calibration, and report
  completeness;
- tokens, turns, retries, wall time, provider refusal/fallback rate, and
  observed plan consumption where available.

Release requires recall non-inferiority at minimum. A cost increase beyond the
historical envelope requires a measured recall or demotion-soundness gain and
explicit user acceptance.

## 7. Final verdict

The proposal should be refined, then built and tested behind `semantic_v1`.
The architectural move from phase-wide model nicknames to typed per-work-unit
authority is high leverage and directly addresses:

- silent alias/model/effort drift;
- underpowered negative adjudication;
- phase-wide over-spend;
- refusal/fallback-induced false negatives;
- weak attribution of model choice to an exact work obligation.

It cannot by itself guarantee a recall increase. It closes important
application and evidence-integrity mechanisms; held-out audits must establish
the outcome.

Do not cut over on the recommendation as currently written. Clear B1-B7,
freeze and hash the legacy profile, add full transition/effort/service-tier
receipts, then run shadow and paired evaluation. Until that evidence exists,
legacy Claude remains the production default and the new routes remain
experimental.

## 8. Official sources

OpenAI:

- https://developers.openai.com/api/docs/guides/latest-model
- https://developers.openai.com/api/docs/models/gpt-5.6-sol
- https://developers.openai.com/api/docs/models/gpt-5.6-terra
- https://developers.openai.com/api/docs/models/gpt-5.6-luna
- https://developers.openai.com/api/pricing

Anthropic:

- https://platform.claude.com/docs/en/about-claude/models/overview
- https://platform.claude.com/docs/en/about-claude/models/migration-guide
- https://code.claude.com/docs/en/model-config

End of review.
