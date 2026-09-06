# Plamen Claude profile/auth/stream integration design

Date: 2026-07-28  
Scope: Claude headless transactional workers only; the same authority must
eventually be consumed by every other Claude print-mode launcher.  
Reviewed implementation root:
`<LOCAL_USER_ROOT>\plamen-codex-implementation`  
Reviewed committed base: `67a0f85adc7a8169d79a286908b00bef7adb764a` plus
the uncommitted P0-AM worktree as observed at 2026-07-28 10:06 EEST.

This document is an integration design. It changes no core file, launches no
provider, and authorizes no cutover.

## 1. Verdict

The three new building blocks are useful, but they are **not safe to wire into
the driver unchanged**:

1. `claude_headless_profile.py` is the right shape for an exact v2 init
   contract and canonical security flags.
2. `claude_auth_route.py` correctly identifies the central billing/auth
   hazard: an ambient API credential can silently outrank stored subscription
   OAuth.
3. `claude_attempt_profile.py` has a strong private-directory and
   post-process cleanup substrate.

The missing integration is not a few driver arguments. It is an
attempt-lifecycle transaction:

```
durable startup permit
  -> exact executable/version observation
  -> attempt-independent Claude policy in WorkPlan
  -> final AttemptArm + process-scope identity
  -> auxiliary-root lease
  -> private Claude profile/auth/settings materialization
  -> exact argv/environment WER arm
  -> natural provider exit + stream-json validation
  -> exhaustive process-scope closure
  -> profile revocation
  -> auxiliary-root revocation
  -> receipt replay
  -> PhaseIO incorporation
```

`worker_execution_receipts.py` (WER), not `plamen_driver.py`, must own the
profile from materialization through revocation. WER is the only layer that
owns the real `OwnedProcessScope` and can prove population zero. The driver
should compile semantic policy; it must not become credential-lifecycle
authority.

The immediate cutover blockers are:

- production `_run_transactional_headless_leaf()` emits stream-json but does
  not supply `provider_stdout_evidence_configuration`;
- current driver commands do not carry a complete v2 secure profile;
- explicit `--settings` bytes are not bound by WER, so exact-consumer hook
  authority can drift even though MCP config bytes are bound;
- the current environment filter preserves ambient `ANTHROPIC_API_KEY` while
  deleting every `CLAUDE_CODE_*` value, including an explicitly selected OAuth
  token and useful functional hardening controls;
- the private attempt profile overrides `HOME`, `USERPROFILE`, `APPDATA`, and
  `LOCALAPPDATA`, which can break compiler/package-manager/keychain discovery
  and therefore cannot be introduced without ecosystem fixtures;
- the attempt profile is bound only to a process-scope string, not the startup
  epoch, auxiliary lease, outer AttemptArm, WorkPlan, auth route, or executable
  observation;
- the current stored-subscription materializer assumes a readable
  `.credentials.json`; that is not a portable proof for macOS Keychain-backed
  installs or every future Claude Code credential store.

## 2. Code-grounded current state

Line numbers below refer to the observed worktree, not the old committed base.

| Area | Current code | What is already sound | Remaining integration defect |
|---|---|---|---|
| Parent environment filter | `plamen_driver.py:817-861` | strips nested Claude session identity | blanket `CLAUDE_CODE_*` removal also strips selected OAuth and functional controls; all other ambient secrets remain |
| Startup permit | `plamen_driver.py:7342-7431` | durable epoch receipt is replayed immediately before worker preparation | must remain bound through WorkPlan, AttemptArm, WER prelaunch, completion, and incorporation |
| Exact-consumer settings | `plamen_driver.py:14251-14423` | policy, settings, empty MCP config, and output receipt gate are constructed | settings bytes/path are not WER-bound |
| Exact-consumer argv | `plamen_driver.py:14456-14478` | uses `dontAsk`, explicit tools, empty setting sources, strict empty MCP | tool order differs from canonical profile order; lacks `--prompt-suggestions false`; WER does not bind `--settings` |
| Transactional Claude command | `plamen_driver.py:51996-52086` | canonical `-p`, `stream-json`, verbose, session ID, no persistence | general launch has no compiled profile; no-MCP path uses inline settings/MCP instead of safe mode; MCP path has no selected strict config |
| Transactional environment | `plamen_driver.py:51939-51953` | explicit additional operational values | starts from the entire ambient environment; auth route is neither selected nor recorded |
| Production runtime call | `plamen_driver.py:52099-52129` | passes startup permit into the shared transaction | does not pass provider stdout policy or a Claude profile/auth request |
| Headless WorkPlan | `headless_worker_runtime.py:495-608` | carries startup permit and optional stream policy in completion policy | Claude stream policy remains optional; no profile/auth/version policy is bound |
| Headless adapter | `headless_worker_runtime.py:708-730` and `worker_transaction.py:121-143` | plan/adapter stream and startup policies are exact-equality checked | no typed Claude attempt-profile request or auth receipt |
| Outer AttemptArm | `worker_transaction.py:2244-2287` | final attempt and process-scope identity exist before provider execution | this is the first point where a profile lease can be bound without inventing identity |
| WER command grammar | `worker_execution_receipts.py:891-1278` | strict stream command, v2 tools/permission/MCP cross-binding, parser runtime binding | no explicit settings binding; `--disallowedTools` is not cross-bound; dynamic profile path lifecycle is absent |
| WER process lifecycle | `worker_execution_receipts.py:4280-4594`, `4828-4915` | arm precedes launch; owned scope; natural process observation; startup replay; exact process closure | no profile materialization/revocation or auth-route replay |
| Attempt profile | `claude_attempt_profile.py:701-1045` | private ACL/mode, no-follow removal, opaque normal-closure token | no auxiliary/startup/arm binding; no prelaunch abort; emergency closure cannot authorize cleanup; global home overrides are high-risk |
| Headless security profile | `claude_headless_profile.py:101-319` | digest-bound canonical flags and v2 init policy | no settings/MCP file authority in the profile object; route-to-`apiKeySource` linkage is external |
| Auth route | `claude_auth_route.py:163-335` | redacted precedence receipt and removal of competitors | availability booleans are caller assertions; no environment-receipt replay function; `apiKeyHelper` cannot survive synthesized empty settings; custom endpoint semantics are erased |
| Toolchain snapshot version | `audit_snapshot.py:2317-2398`, `2436-2475` | bounded owned `--version` probe and executable digest | uses bare `claude`, not necessarily the configured `CLAUDE_BIN`; output is buried in a component digest and not consumable by the launch compiler; wrapper transitive bytes may remain unbound |

The non-integration is mechanically confirmed: outside their own modules and
tests, there are no production imports/calls to
`materialize_claude_attempt_profile`,
`compile_claude_headless_profile`, `compile_claude_auth_environment`, or
`parse_claude_code_version`.

## 3. Required ownership model

### 3.1 Driver owns semantic intent, never profile lifetime

`_run_transactional_headless_leaf()` should supply a typed,
attempt-independent `ClaudeLaunchPolicy` containing:

- exact desired auth route class;
- exact executable observation digest;
- exact Claude Code version;
- model denominator;
- permission mode;
- exact built-in tool denominator;
- required and forbidden tools;
- customization mode (`SAFE_MODE` or `BOUND_SETTINGS`);
- exact named MCP server denominator;
- exact external settings-policy digest when applicable;
- expected `apiKeySource` values for the pinned CLI protocol;
- stream ceilings and expected session ID.

It must not:

- copy credentials;
- create a profile directory;
- choose a caller-supplied writable root;
- delete a profile;
- claim process closure;
- infer auth from cost fields.

### 3.2 WorkPlan owns the attempt-independent policy

Extend the v2 completion policy with a single normalized object, for example:

```json
{
  "claude_launch_security": {
    "schema": "plamen.claude_launch_security.v1",
    "headless_profile": { "...": "replayed claude_headless_profile" },
    "auth_route_policy": {
      "desired_route": "STORED_SUBSCRIPTION_OAUTH",
      "expected_init_api_key_sources": ["subscription"]
    },
    "executable_observation_sha256": "<sha256>",
    "settings_authority": {
      "mode": "NONE_OR_SAFE_MODE"
    },
    "mcp_authority": {
      "server_names": [],
      "source_manifest_sha256": null
    }
  }
}
```

The WorkPlan must bind policy and placeholders, not a concrete attempt profile
path or secret. Retry creates a new attempt/profile while preserving the same
semantic policy.

The existing
`provider_stdout_evidence_configuration` remains a separate completion
contract, but its `expected_init_contract` must equal the normalized headless
profile's expected init contract byte-for-byte. No caller may supply two
independently authored variants.

### 3.3 WorkerTransaction owns attempt identity and the outer arm

`execute_worker_transaction()` already creates:

- final attempt ID (`worker_transaction.py:2158-2178`);
- final process-scope identity (`:2244-2265`);
- outer arm digest (`:2286-2287`).

After the outer arm is durable, it should pass a typed profile request to WER
containing those three identities, the startup permit, and the replayed
WorkPlan Claude policy. This avoids the circularity in which a lease wants an
AttemptArm digest while its path changes the eventual provider argv.

The outer WorkerTransaction arm is the correct lease authority. WER's inner
provider arm then records the materialized path/argv/environment.

### 3.4 WER owns the concrete profile and cleanup

WER should:

1. replay startup authority before any auxiliary allocation;
2. validate the profile/auth/version policy before allocation;
3. reserve and arm an opaque auxiliary root using the outer AttemptArm digest
   and exact process-scope identity;
4. materialize the private profile under that leased root;
5. build the final child environment and final concrete argv;
6. bind both into WER's provider arm;
7. replay startup permit immediately before `Popen`;
8. launch under the exact `OwnedProcessScope`;
9. naturally observe root exit and close the complete process scope;
10. replay settings, MCP config, auth classification, and profile binding;
11. revoke the profile **after population zero**;
12. revoke the enclosing auxiliary lease;
13. persist both redacted revocation receipts;
14. validate stream-json and outputs;
15. mint completion only if every required revocation and replay succeeded.

The profile object must never escape back to the driver.

## 4. Stored-subscription compatibility

The legacy Claude path should default to an explicit route policy, not “whatever
the ambient environment chooses.” For the requested legacy path:

```
desired_route = STORED_SUBSCRIPTION_OAUTH
```

Before constructing the child environment:

- inspect the source route locally without recording credential values;
- reject an unavailable requested route;
- remove cloud selectors, `ANTHROPIC_AUTH_TOKEN`,
  `ANTHROPIC_API_KEY`, `apiKeyHelper`, `CLAUDE_CODE_OAUTH_TOKEN`, and proxy/base
  URLs that would change the selected stored route;
- copy/materialize only the supported stored credential mechanism;
- require the init event's `apiKeySource` to match the pinned version's
  expected vocabulary;
- record a redacted auth-route receipt and exact key-denominator digest;
- never infer billing route from `total_cost_usd`.

The current profile's unconditional `.credentials.json` copy is not a
cross-platform proof. Use a versioned host credential provider:

| Host/store | Permitted implementation | Failure behavior |
|---|---|---|
| Windows/Linux file-backed store | Open exact no-follow credential file; copy through private handle into leased profile; verify copy without publishing raw bytes | fail closed before provider arm if source/store format is unsupported |
| macOS Keychain-backed store | Use a controlled official CLI/keychain-compatible route proven by a dedicated integration fixture; do not pretend `.credentials.json` is sufficient | route unavailable/debt; require user-selected setup-token or supported global-keychain mode |
| Explicit `CLAUDE_CODE_OAUTH_TOKEN` | Preserve only when this is the selected route; never blanket-strip it | fail closed if absent or if init reports another source |
| API key/cloud route | opt-in only; preserve exactly that route and its required endpoint/provider selector | never silently fall back from subscription |
| `apiKeyHelper` | only when the bound settings profile contains the exact helper and WER binds its settings bytes | current synthesized-empty-settings path must reject it |

Do not use `--bare` for stored subscription OAuth. The reviewed provider
research records that bare mode skips OAuth/keychain reads.

The official research basis is captured in
`Downloads\Plamen_Claude_Provider_Authentic_Channel_Research_2026-07-27.md`,
especially lines 50, 56-65, 75-99, and 224-289. Primary references recorded
there are:

- https://code.claude.com/docs/en/headless
- https://code.claude.com/docs/en/cli-usage
- https://code.claude.com/docs/en/authentication
- https://code.claude.com/docs/en/agent-sdk/overview

### Privacy correction

`claude_attempt_profile.py:592-624` and `:992-1015` put long-lived
credential/source SHA-256 values into the returned binding. That avoids raw
secret disclosure but creates a stable secret-derived correlator and an
unnecessary offline oracle. The durable receipt should instead record:

- source store class;
- source file identity/size where applicable;
- exact-copy verification boolean;
- a run-scoped opaque materialization ID;
- profile/lease/auth-policy digests that do not hash raw credential content.

If an exact credential digest is needed transiently to validate the copy, keep
it in memory or in the private profile root that is deleted; do not publish it
to the ordinary run artifacts.

## 5. Filtered child environment reconstruction

Replace direct use of `_filtered_child_subprocess_environ()` for Claude workers
with one compiler, conceptually:

```python
compile_claude_child_environment(
    ambient,
    desired_auth_route,
    attempt_profile_environment,
    phase_environment_policy,
)
```

Order is load-bearing:

1. normalize names case-insensitively and reject collisions;
2. classify auth from the original environment/settings/store;
3. compile the selected route and remove every competing route source;
4. remove all parent Claude identity/session variables;
5. default-deny unknown `CLAUDE_CODE_*` variables;
6. re-add only the selected auth variable, when applicable;
7. add reviewed functional controls;
8. overlay private profile paths;
9. add phase/toolchain variables from a named allowlist;
10. bind names and an in-memory-value digest in the WER arm; persist no values;
11. classify again from the final child environment and require the selected
    route to equal policy.

Reviewed functional controls should include, when supported by the pinned
version:

- subprocess environment scrubbing;
- disabling claude.ai MCP/connectors when local exact MCP is the only authority;
- disabling updater/telemetry/error reporting/nonessential model calls;
- disabling automatic memory for exact consumers;
- explicit temp paths under the leased root;
- explicit operational output ceilings.

Do not copy the entire ambient environment. In particular, stored-subscription
workers should not inherit arbitrary `ANTHROPIC_*`, AWS/GCP/Azure credentials,
GitHub tokens, SSH agent sockets, or unrelated service keys. Phase/tool needs
must be explicitly named.

### HOME/APPDATA conflict

Do **not** immediately ship the environment at
`claude_attempt_profile.py:980-991`. Replacing:

- `HOME`;
- `USERPROFILE`;
- `APPDATA`;
- `LOCALAPPDATA`

can hide or relocate Cargo/Rustup, npm, Foundry, Solana, Aptos, Sui, Stellar,
Go, Git, proxy, certificate, and macOS Keychain-related configuration from
Claude's Bash/tool subprocesses. That can reduce recall by making builds and
PoCs fail.

Choose one of these only after fixtures:

1. Preferred: use `CLAUDE_CONFIG_DIR` and explicit Claude flags while
   preserving toolchain home variables, if the pinned CLI proves it does not
   mutate global Claude state.
2. If a private HOME is mandatory, compile explicit, snapshot-bound,
   ecosystem-specific toolchain environment mappings and writable caches under
   separate auxiliary leases. Never assume an empty HOME is behaviorally
   equivalent.
3. If neither can be proved for a host/version, do not cut over that host;
   record capability debt and keep the prior launch mode non-proof-grade.

## 6. Safe mode versus bound settings/MCP

### 6.1 No-MCP ordinary workers

Use `customization_mode=SAFE_MODE` and the canonical flags emitted by
`compile_claude_headless_profile()`:

- exact permission mode;
- `--safe-mode`;
- `--disable-slash-commands`;
- `--setting-sources=`;
- `--no-chrome`;
- `--prompt-suggestions false`;
- exact `--tools` denominator.

Remove the current inline
`--settings SUBPROCESS_ISOLATION_PAYLOAD --strict-mcp-config --mcp-config
SUBPROCESS_ISOLATION_PAYLOAD` path at `plamen_driver.py:52075-52085` for these
workers. Safe mode must have no MCP config and init must report no MCP,
plugins, skills, agents, or slash commands.

Use `--tools` as the single built-in authority. Under v2, either forbid
`--disallowedTools` entirely or mechanically derive and cross-bind it. The
cleaner rule is to forbid it: a whitelist plus a separately authored deny list
creates two mutable descriptions of the same capability boundary.

### 6.2 Exact consumers with hook-enforced I/O

The phases in `_CLAUDE_EXACT_CONSUMER_PHASES`
(`axis_coverage`, `chain_agent2`, `chain_iter2`, `report_index`) require the
explicit settings overlay produced by `claude_phase_tool_policy.py:340-379`.
They therefore use `customization_mode=BOUND_SETTINGS`, not safe mode:

- `permission_mode=dontAsk`;
- exact sorted tools `Edit,Glob,Grep,Read,Write`;
- explicit `--settings <absolute bound path>`;
- strict explicit empty MCP config;
- empty setting sources;
- remaining canonical isolation flags.

WER must bind:

- settings path, size, and SHA-256;
- settings JSON strict/canonical parse;
- exact hook executable and policy path;
- hook executable/policy bytes in implementation closure;
- MCP config path, size, SHA-256, and empty server denominator;
- prelaunch and post-process byte equality.

The current WER binds only MCP config (`worker_execution_receipts.py:1184-1230`);
it does not inspect `--settings`. This must be closed before exact-consumer
stream policy is enabled.

### 6.3 MCP consumers

`rag_sweep` is the current declared MCP phase
(`plamen_types.py:2455-2458`, `:2793-2796`). It should use:

- `customization_mode=BOUND_SETTINGS`;
- exact required server names, initially the minimum server denominator needed
  by the phase (normally `unified-vuln-db`, not all installed servers);
- a strict, private, attempt-owned MCP config containing only those servers;
- exact server config byte binding;
- init evidence requiring each named server to be connected;
- MCP failure as explicit phase debt/fallback, never silent tool absence.

The config compiler must copy only selected server definitions from the
installed Plamen MCP manifest, validate command/cwd/env paths, and avoid
persisting secret values in public receipts. It must not load the user's full
global MCP set.

For secrets such as a Solodit key currently sourced from Claude settings,
project only the explicitly required value into the selected MCP server's
private environment/config. Do not put it back into the root model
environment.

## 7. Startup, lease, arm, and process-scope binding

Extend `claude_attempt_profile` binding v3 to require:

- run ID;
- startup permit binding/digest and startup epoch;
- outer WorkerTransaction AttemptArm digest;
- WorkPlan digest;
- attempt ID;
- process-scope identity;
- auxiliary lease binding SHA-256;
- Claude launch-security policy SHA-256;
- executable observation SHA-256;
- redacted auth-environment receipt SHA-256;
- settings/MCP authority digests;
- trusted cwd denominator;
- private-root identity and directory-security evidence.

The auxiliary lease must be created through
`reserve_auxiliary_writable_root()` and armed with the outer AttemptArm digest
and exact process-scope identity. A caller-supplied runtime path is not
acceptable production authority.

WER should pass the leased root as an additional writable root to
`OwnedProcessScope`. The profile may use a child of that root, preserving the
current private ACL/mode installation. The process can write only its staging
output and this leased profile root.

### Prelaunch failures

If cancellation, version/profile/auth/settings validation, `Popen`, or scope
binding fails before a process begins, use the auxiliary lease's
`abort_before_process_scope()` to delete all profile bytes and persist a
prelaunch-abort receipt. Profile cleanup must not depend on a closure token for
a scope that never ran.

### Normal closure

After `process_tree.close()` proves `closed=True` and
`population_zero_proven=True`:

1. mint a profile-bound closure token from the exact scope;
2. revoke the profile;
3. replay profile revocation;
4. mint/replay the auxiliary lease closure;
5. revoke the enclosing root;
6. only then consider completion.

### Emergency closure

Cleanup authority and success authority must be separate:

- an emergency closure may never make a provider execution successful;
- if emergency cleanup nevertheless proves exact population zero, it should be
  allowed to delete credentials under a distinct
  `EMERGENCY_ZERO_POPULATION_CLEANUP` receipt;
- if population zero is unproven, do not race the process by deleting its
  profile. Quarantine the lease and let startup reconciliation own recovery;
- any profile cleanup/replay failure produces terminal provider debt and blocks
  PhaseIO incorporation.

The current profile rejects every emergency-closed scope
(`claude_attempt_profile.py:842-845`), which can unnecessarily retain secrets
even when zero population is proven. Refine this into cleanup-only authority,
not completion authority.

## 8. Exact executable and version observation

Before compiling the headless profile:

1. resolve the same configured `CLAUDE_BIN` used by the WorkPlan;
2. reject aliases/reparse drift;
3. hash the executable/wrapper;
4. execute that exact path with `--version` through the owned native process
   runner, bounded stdout/stderr, no provider query;
5. parse the complete canonical output with
   `parse_claude_code_version()`;
6. record a digest-bound observation;
7. compile only flags supported by that version;
8. recheck executable bytes immediately before launch;
9. require init `claude_code_version` to equal the observation.

Do not use `preflight_pty_transports.get_claude_version()` as authority: it
returns `"unknown"` and shares that cache slot on failure
(`preflight_pty_transports.py:100-125`). It is operational legacy code.

Refactor/expose the owned probe in `audit_snapshot.py:2333-2398`, but fix its
bare `"claude"` command at `:2452`. A `CLAUDE_BIN` override and PATH-selected
`claude` can be different executables.

On Windows/npm installations, hashing only `claude.cmd` may not bind the
mutable Node/JavaScript implementation it invokes. Bind the transitive
entrypoint/runtime closure, or mark the observation
`TRANSITIVE_IMPLEMENTATION_UNBOUND` and refuse proof-grade cutover. Native
self-contained installers can use direct executable binding after platform
signature/version checks.

Version support must be a reviewed compatibility table, not “version parses,
therefore every flag exists.” Unknown future versions require a fixture update
or explicit degraded route.

## 9. `provider_stdout_evidence_configuration`

For every transactional Claude headless worker, construct exactly one object:

```python
{
    "schema": CLAUDE_STREAM_STDOUT_CONFIGURATION_SCHEMA,
    "expected_session_id": claude_stream_session_id,
    "expected_init_contract": headless_profile["expected_init_contract"],
    "max_line_bytes": DEFAULT_MAX_LINE_BYTES,
    "max_stream_bytes": configured_stdout_limit,
}
```

Rules:

- use the already deterministic session ID at
  `plamen_driver.py:51980-51994`;
- `max_stream_bytes` must equal the WorkPlan provider stdout ceiling;
- the expected init contract must come from the replayed profile, not be
  reconstructed in the driver;
- pass it at `plamen_driver.py:52099-52129`;
- `prepare_headless_worker()` places it in completion policy
  (`headless_worker_runtime.py:569-599`);
- `HeadlessModelAdapter` must carry the exact same object
  (`headless_worker_runtime.py:708-727`);
- WorkerTransaction must retain its present exact-equality check
  (`worker_transaction.py:2007-2040`);
- WER must derive the command contract and parser-runtime binding and validate
  the final stream;
- absence on a Claude headless WorkPlan is a compile-time error, not optional
  legacy behavior.

Codex plans must continue to reject this Claude-only policy.

## 10. Current WER argv conflicts

The new WER grammar at `worker_execution_receipts.py:906-1278` correctly
requires:

- canonical `-p`;
- exact stream-json/verbose/session/model/no-persistence flags;
- no resume/continue/fork/partial-forwarding aliases;
- full v2 profile;
- exact tool order/equality;
- exact permission argv;
- safe-mode/MCP exclusivity;
- strict MCP config and exact server denominator.

The current driver will fail that grammar after stream policy is enabled:

1. General workers at `plamen_driver.py:52050-52085` have no complete profile:
   no `--tools`, `--disable-slash-commands`, `--setting-sources=`,
   `--no-chrome`, or `--prompt-suggestions false`.
2. Exact consumers at `:14468-14478` omit
   `--prompt-suggestions false`.
3. Exact-consumer tool order is `Read,Glob,Grep,Write,Edit`; profile
   normalization produces `Edit,Glob,Grep,Read,Write`.
4. `--disallowedTools` is added at `:52056-52074` but is not part of the v2
   profile authority.
5. WER requires an MCP path to be a real file; the general no-MCP driver
   currently passes inline JSON as `--mcp-config` at `:52075-52085`.
6. WER has no `--settings` singleton/path/byte binding, so a malformed,
   duplicated, substituted, or post-arm-mutated settings overlay is not
   rejected by the command contract.
7. `claude_headless_profile` BOUND_SETTINGS emits only generic profile flags;
   the caller must attach a separately bound settings and strict MCP authority.
   This attachment must be one typed compiler, not arbitrary list extension.

Resolve these before enabling v2 in the production driver.

## 11. Required code changes by function

### New/extended typed providers

- `claude_attempt_profile.py`
  - add lease/startup/outer-arm/WorkPlan/auth/version/settings bindings;
  - support an already leased parent;
  - remove durable credential-content hashes;
  - add cleanup-only emergency-zero semantics;
  - make home-variable policy explicit instead of unconditional.
- `claude_auth_route.py`
  - add replay for `AUTH_ENVIRONMENT_SCHEMA`;
  - replace caller-trusted availability booleans with observed store/settings
    evidence;
  - bind exact desired endpoint semantics for non-subscription routes;
  - map route to exact init `apiKeySource` vocabulary by CLI version.
- `claude_headless_profile.py`
  - carry or reference typed settings authority for BOUND_SETTINGS;
  - reject a profile whose auth-source denominator is broader than its auth
    route policy;
  - gate flags by exact version observation.
- add one `claude_executable_observation.py` or expose an equivalent strict
  provider from `audit_snapshot.py`.
- add one `claude_child_environment.py`; do not further grow the generic
  `_filtered_child_subprocess_environ()`.

### Runtime integration

- `headless_worker_runtime.prepare_headless_worker()`
  - require Claude launch security and stream policy when backend is Claude;
  - derive one from the other and exact-compare;
  - put profile/auth/version/settings policy in completion policy;
  - include the final environment-key denominator.
- `worker_transaction.HeadlessModelAdapter`
  - carry the same typed Claude launch-security request;
  - exact-compare plan versus adapter;
  - bind final attempt/outer-arm/process-scope identities.
- `worker_transaction.execute_worker_transaction()`
  - pass outer arm digest plus typed request to WER;
  - never materialize/delete credentials itself.
- `worker_execution_receipts.run_observed_worker()`
  - own profile/lease materialization;
  - bind actual settings and environment;
  - replay auth/version/startup prelaunch and post-close;
  - own profile then lease revocation;
  - persist redacted profile/auth/revocation evidence.
- `worker_execution_receipts._claude_stream_stdout_binding()`
  - bind one exact `--settings` file in BOUND_SETTINGS mode;
  - reject settings in SAFE_MODE;
  - forbid or exact-bind `--disallowedTools`;
  - include settings binding in `command_contract.headless_profile`;
  - remeasure settings/MCP after process close and during receipt replay.
- `plamen_driver._run_transactional_headless_leaf()`
  - compile semantic profile from phase/LaunchSpec/tool boundary;
  - use one environment compiler;
  - pass required stream/profile/auth policy to the runtime;
  - remove ad hoc profile/settings/deny-list argv composition.

### All Claude print-mode call sites

The following are not allowed to remain a second, weaker Claude headless
architecture:

- verification recovery launch at `plamen_driver.py:32128-32220` currently
  emits `--output-format json`;
- severity adjudication launch at `:43130-43182` currently emits JSON, inline
  empty MCP, and an unrelated environment policy;
- any skeptic/negative provider path that builds Claude argv through
  `canonical_backend_argv()` around `:41119-41125`;
- dynamic verifier/recovery helpers and any future Claude print-mode launcher.

Migrate each to the same typed WorkPlan/WER adapter. Until migrated, mark it
legacy/non-proof-grade; do not claim universal Claude stream/profile safety.

## 12. Fixture-first red denominator

Write these as red tests before integration. Each test must assert that no
provider process is created on prelaunch rejection and that no secret value
appears in receipts/logs.

### A. Driver and WorkPlan propagation

1. `test_transactional_claude_requires_v2_profile_and_stream_policy`
   - current `_run_transactional_headless_leaf()` should fail because it omits
     the stream policy.
2. `test_driver_profile_expected_init_is_single_source`
   - mutate only the driver copy; WorkPlan compilation rejects it.
3. `test_claude_workplan_cannot_omit_profile_or_auth_policy`
   - Claude missing either policy fails; Codex carrying either fails.
4. `test_driver_general_no_mcp_uses_safe_mode_not_inline_config`.
5. `test_exact_consumer_uses_bound_settings_and_sorted_tools`.
6. `test_disallowed_tools_cannot_create_second_capability_denominator`.
7. `test_retry_preserves_policy_but_receives_fresh_attempt_profile`.

Extend:

- `test_headless_driver_cutover_p0_am.py:603-654`;
- `test_headless_claude_stream_policy_p0_am.py`;
- `test_wer_workplan_stream_policy_consistency_p0_am.py`;
- `test_worker_work_plan_v2_roster_binding_p0_am.py`.

### B. Settings and MCP byte authority

8. settings changed after arm/before `Popen` rejects launch.
9. settings changed after root exit rejects completion.
10. duplicated `--settings`, relative path, inline JSON, missing file, symlink,
    junction/reparse point, oversized file, duplicate JSON key, or unknown
    setting field fails closed.
11. exact-consumer settings hook path/policy digest mismatch fails.
12. safe mode plus any settings/MCP authority fails.
13. bound settings without one strict MCP config fails, including empty MCP.
14. MCP config server denominator differs from expected init fails.
15. MCP server entry command/cwd/env drift fails.
16. unselected installed MCP server never appears in argv/init.
17. `rag_sweep` with unavailable `unified-vuln-db` records explicit fallback
    debt and does not pretend MCP applied.

Extend:

- `test_wer_claude_command_and_runtime_fingerprint_p0_am.py`;
- `test_claude_phase_tool_boundary_driver_p1_f.py`;
- `test_claude_headless_profile_p0_am.py`.

### C. Auth-route fidelity

18. ambient API key + desired stored subscription removes API key and init must
    report subscription.
19. ambient auth token, API key, OAuth token, helper, proxy URL, and stored
    credential select only the requested route.
20. blanket prefix filtering may not delete a selected OAuth token.
21. stored subscription unavailable fails before profile/worker arm.
22. helper selected while synthesized settings omit helper fails.
23. route receipt mutation or environment key-set mutation fails replay.
24. init `apiKeySource` differs from selected route fails.
25. cost field cannot affect route classification.
26. credential values and credential-derived public hashes are absent from all
    JSON/log/exception artifacts.
27. cloud selectors conflict; cloud credential variables without selected
    cloud route are absent from child.
28. custom base URL is preserved only under an explicitly bound non-subscription
    endpoint policy.

Extend `test_claude_auth_route_p0_am.py`.

### D. Profile/lease/process lifecycle

29. startup epoch rotates between WorkPlan prepare and profile allocation:
    no root is allocated.
30. startup epoch rotates after profile allocation/before `Popen`: prelaunch
    abort deletes credential root and records debt.
31. profile binding substitutes run/WorkPlan/arm/attempt/scope/lease:
    prelaunch rejection.
32. cancellation before scope creation deletes profile through lease abort.
33. `Popen` failure deletes profile through lease abort.
34. process exits while descendant survives: profile remains quarantined until
    population-zero recovery; no completion.
35. normal population-zero closure revokes profile before auxiliary root.
36. profile revocation failure blocks completion and incorporation.
37. emergency closure with proven zero performs cleanup-only revocation and
    still emits provider debt.
38. emergency closure without proven zero quarantines; startup recovery removes
    it later.
39. crash after credential copy, after lease arm, after process attach, after
    scope close, after profile revoke, and after lease revoke is replayable and
    cannot mint completion twice.
40. worker-created symlink/junction/hardlink inside profile cannot make cleanup
    follow/delete outside bytes.
41. two concurrent attempts have disjoint profile roots, credentials, temp
    paths, sessions, and scope identities.
42. old singleton startup ALLOW cannot authorize a new profile epoch.

Extend:

- `test_claude_attempt_profile_p0_am.py`;
- `test_auxiliary_writable_root_lease_p0_am.py`;
- `test_auxiliary_writable_root_recovery_p0_am.py`;
- `test_worker_execution_receipts.py`;
- `test_worker_transaction_contracts_p0_am.py`.

### E. Version/executable binding

43. configured `CLAUDE_BIN` differs from PATH `claude`; observation and launch
    must use configured exact path.
44. malformed, multi-line, noncanonical, old, or future unsupported version
    output rejects the profile.
45. executable changes after version observation or before `Popen` rejects.
46. `.cmd` wrapper unchanged but transitive JS target changes rejects or
    records explicit unbound capability debt.
47. version supports stream-json but not one required profile flag: no launch.
48. init version differs from preflight version: stream rejected.

Extend `test_claude_headless_profile_p0_am.py`,
`test_audit_snapshot_*`, and WER runtime-fingerprint tests.

### F. Ecosystem/toolchain compatibility

Run offline fake-CLI/tool discovery under the exact final child environment for
each host matrix:

49. EVM: `forge`, `cast`, `solc`, `slither`, npm/Node config/cache discovery.
50. Solana: `solana`, Anchor, Cargo/Rustup.
51. Aptos: Aptos CLI, Move compiler, Cargo/Rustup where used.
52. Sui: Sui CLI, Move, Cargo/Rustup.
53. Soroban: Stellar CLI, Cargo/Rustup.
54. L1 Go/Rust: Go env/module cache, Cargo/Rustup, native build tools.
55. Git config, CA/proxy paths, temp path, Unicode/spaces/long paths.
56. prove that private HOME versus preserved HOME produces no command
    availability or build-result drift; if it does, private HOME is rejected.
57. Windows native, WSL2 native Linux filesystem, Ubuntu LTS, and macOS.
58. BB wrapper launches the same profile/auth/stream policy and does not import
    an ambient installed Plamen runtime.

These are compatibility fixtures, not live model calls.

### G. Controlled official CLI tests (only after user approval)

Retain the controlled suite from the provider research artifact:

- valid trivial artifact;
- fake result string nested in Bash output;
- subagent attribution;
- background child and natural exit;
- forged session transcript has no effect;
- auth failure/rate limit/timeout/cancel;
- Linux/macOS/WSL2/native Windows;
- stored subscription route and usage behavior with a dedicated test profile.

No controlled test can replace the offline authority tests above.

## 13. Checkpoint sequence

Implement in small checkpoints:

1. settings-binding and WER argv fixes;
2. executable/version observation;
3. auth environment receipt replay and final-env compiler;
4. attempt profile v3 bindings and privacy correction;
5. WER-owned profile/lease lifecycle with fake CLI only;
6. production `_run_transactional_headless_leaf()` v2 policy;
7. no-MCP safe-mode lane;
8. exact-consumer bound-settings lane;
9. `rag_sweep` selected-MCP lane;
10. recovery/severity/skeptic/dynamic-verifier migration;
11. ecosystem/cross-OS/toolchain/BB matrix;
12. full fast lane and fault/recovery suite;
13. optional user-approved controlled Claude CLI tests;
14. only then consider cutover.

At every checkpoint:

- new red fixture first;
- focused green;
- WER/WorkerTransaction/startup/lease blast-radius suite;
- complete fast lane;
- no raw credential/provider calls;
- no commit/push/cutover until independent review.

## 14. Cross-OS failure semantics

| Platform | Profile security | Process/write proof | Required behavior |
|---|---|---|---|
| Windows native | protected current-token-user DACL, no reparse traversal | Job Object plus existing serialized low-integrity/write authority; stdout producer exclusivity remains unproven | profile cleanup is mandatory; stamp native-Windows stream provenance honestly |
| Linux | owner-only mode, no symlink traversal | cgroup/Landlock path where available | fail before launch when exhaustive scope/write authority is unavailable |
| WSL2 | Linux semantics only on a native Linux root | cgroup/Landlock as available | do not place secret lease on `/mnt/c` and pretend POSIX mode is sufficient |
| macOS | owner-only mode plus Keychain-aware route | platform process-group/write capability as implemented | stored-subscription route requires a dedicated keychain fixture; `.credentials.json` assumption is insufficient |
| Unsupported host | none inferred | none inferred | no proof-grade Claude launch; durable capability debt |

Cleanup errors never silently continue as success:

- before process: prelaunch-abort receipt;
- after scope with zero population: cleanup debt, no incorporation;
- without zero population: quarantine plus startup-recovery debt;
- recovery success permits a fresh attempt, never retroactive completion.

## 15. Acceptance verdict

The proposed profile/auth/stream restructuring is worth building because it
directly removes three real sources of nondeterminism and false safety:

- writable transcript completion authority;
- accidental auth/billing route drift;
- mutable global Claude configuration and unbounded MCP/plugin startup.

But the correct unit of work is the transaction lifecycle above. Wiring only
the profile flags or copying credentials in the driver would create a more
complex system without closing the authority gap and could reduce recall by
breaking the ecosystem toolchain environment.

The design is ready for fixture-first implementation after one narrow
pre-implementation decision: whether the pinned Claude CLI can isolate all
Claude state with `CLAUDE_CONFIG_DIR` while preserving the user's toolchain
HOME. That decision should be settled by offline fake-CLI environment tests
and a user-approved dedicated-profile CLI integration test, not by assumption.

Until then:

- keep overall cutover blocked;
- integrate settings binding and required stream policy first;
- do not wire `claude_attempt_profile.py` unchanged;
- do not claim stored-subscription portability beyond the credential-store
  paths that have passed the host matrix.

