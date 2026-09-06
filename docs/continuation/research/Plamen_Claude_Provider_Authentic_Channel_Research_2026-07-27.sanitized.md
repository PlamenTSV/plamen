# Plamen Claude provider-channel research

Requested artifact date: 2026-07-27  
Evidence observed: 2026-07-28, Europe/Bucharest  
Scope: official Anthropic documentation and read-only local CLI inspection; no model call, production edit, or credential read

## Executive verdict

Plamen should replace transcript-polled PTY completion with Claude Code print mode over a private, bounded `stream-json` stdout channel. The terminal condition should be the CLI's final root `result` message followed by natural exit code 0, exhaustive process-tree closure, and an unchanged parser-valid assigned-output denominator. Session JSONL may remain for resume and forensics, but must never again authorize completion.

This is a material security and reliability improvement, not a complete cryptographic producer-authentication solution:

- In normal Claude Code operation, the root CLI serializes model, tool, and subagent activity into its `stream-json` output; tool text is data inside those envelopes. This removes the concrete defect in which a worker can write a plausible `assistant/end_turn` row directly into its own writable session transcript.
- Anthropic does not document an exclusive-writer guarantee for the CLI stdout handle. A hostile same-user descendant that can inherit, reopen, or duplicate that handle could attempt to inject a top-level JSON line. Native Windows also lacks Claude Code's Bash sandbox. Therefore `stream-json` alone cannot honestly be called cryptographically or adversarially producer-authentic.
- A provider event must remain necessary but insufficient. Plamen must additionally require exact output artifacts, parser success, output stability through scope closure, natural root exit, zero live descendants, and exact replay of the captured bytes. On platforms where descendant I/O isolation cannot be proved, record a degraded provenance capability instead of asserting full authenticity.

The practical recommendation is a two-level claim:

1. **Provider-channel completion**: available now with an exact Claude CLI `stream-json` result channel. This closes the known writable-transcript forgery path.
2. **Hostile-descendant-exclusive producer authenticity**: not established by any documented CLI/SDK flag. It requires a provider-supported authenticated channel or OS isolation that proves only the exact root producer can write the channel.

## Local evidence

The installed executable inspected read-only was:

| Property | Value |
|---|---|
| Path | `<LOCAL_USER_ROOT>\.local\bin\claude.exe` |
| `claude --version` | `2.1.220 (Claude Code)` |
| File/product version | `2.1.220.0` |
| Size | `265,720,480` bytes |
| SHA-256 | `AF5BF1F1B2AADFFC768ECCD787084C6FDF9BA81624CBE96C1C6D9AC1A1550231` |
| Authenticode | Valid; signer `Anthropic, PBC` |
| Auth status | `loggedIn=false`, `authMethod=none`, `apiProvider=firstParty` |

No live provider test was possible or attempted because the inspected profile was not logged in.

Local help confirms that 2.1.220 supports:

- `-p` / `--print`
- `--output-format text|json|stream-json`
- `--input-format text|stream-json`
- `--include-partial-messages`
- `--forward-subagent-text`
- `--replay-user-messages`
- `--session-id`, `--resume`, `--continue`, and session persistence
- built-in tools, `--agents`, MCP configuration, plugins, settings, and permission modes
- `--max-budget-usd`, `--model`, and `--effort`

Local help also says `--bare` skips OAuth and keychain reads and accepts Anthropic authentication only from `ANTHROPIC_API_KEY` or `apiKeyHelper`. Plamen must not use `--bare` when the selected billing route is a user's subscription OAuth.

## What the official interfaces preserve

### CLI print mode

Anthropic describes `claude -p` as the Agent SDK exposed through the CLI, with the same tools, agent loop, and context management as Claude Code. All CLI options work with print mode. `stream-json` is newline-delimited JSON; its final line is a `result` message containing the final response, cost estimate, and session metadata. The CLI supports tools, custom agents, MCP, skills, plugins, settings, continuation, and resume in this mode.

The current documentation also states:

- subagent messages are emitted with `parent_tool_use_id`; main-conversation messages use `null`;
- background subagents and workflows are awaited because their result contributes to final output;
- a root `result` is the end of one agent-loop query;
- print mode can continue or resume sessions by ID;
- large-stream final-line truncation was fixed before the installed 2.1.220 version;
- print mode skips the workspace trust dialog, and invalid settings files can be ignored silently, so Plamen must validate and hash settings before launch rather than trusting CLI diagnostics.

### Streaming input and interactive behavior

`--input-format stream-json` and the Agent SDK's streaming input mode preserve programmatic interactivity: queued messages, interruptions, permission requests, full tools and MCP, session management, real-time feedback, and multi-turn context. They do not preserve the terminal TUI itself. Terminal-only commands such as `/login` are unavailable in print mode.

For Plamen's autonomous one-task workers, the TUI is not a required semantic capability. Deterministic permission policy and a bounded input stream are preferable to keypress automation. If a phase genuinely needs mid-turn user input, use a typed streaming-input controller or a permission-prompt MCP tool; do not revive terminal scraping.

### Agent SDK package

The Python and TypeScript Agent SDK packages expose typed `AssistantMessage`, `SystemMessage`, `StreamEvent`, and final `ResultMessage` objects, plus tools, subagents, sessions, interrupts, hooks, MCP, and permissions. However, Anthropic's SDK overview instructs developers to use API-key or supported cloud-provider authentication and says third-party developers may not offer claude.ai login or subscription rate limits without prior approval.

Accordingly:

- for Plamen's legacy subscription-backed Claude path, prefer the user's installed Claude CLI in print mode;
- do not embed or redistribute a subscription login flow;
- do not copy credentials into a product-managed account;
- if Plamen later offers an Agent SDK package path, treat it as an API-key/cloud-provider backend unless Anthropic explicitly approves another arrangement.

### Subscription authentication and cost

Official authentication precedence applies to the CLI and surfaces that wrap it:

1. cloud-provider credentials;
2. `ANTHROPIC_AUTH_TOKEN`;
3. `ANTHROPIC_API_KEY`;
4. `apiKeyHelper`;
5. `CLAUDE_CODE_OAUTH_TOKEN`;
6. stored subscription OAuth.

Therefore print mode is not automatically API-billed. It can use Pro, Max, Team, or Enterprise subscription OAuth when no higher-precedence credential is present. `claude setup-token` can create a one-year subscription OAuth token for scripts, but it cannot establish Remote Control sessions or fetch claude.ai connectors; locally configured MCP servers still work.

Plamen must bind and record a redacted auth-route classification before each run. An ambient API key silently outranks subscription OAuth and could change both billing and rate limits. Never infer the route from `total_cost_usd`: Anthropic says result cost fields are client-side estimates, not authoritative billing data. Subscription users also receive a one-hour prompt-cache TTL automatically.

`stream-json` is a local serialization choice, not a model-quality or token-cost multiplier. Omitting partial-token events and forwarded subagent text reduces local I/O without reducing model reasoning.

## Code-grounded diagnosis of the current Plamen path

The current implementation has already encoded the core concern:

- `scripts/worker_execution_receipts.py::_claude_pty_bridge_binding` binds the exact bridge, host manifest, child executable digest, prompt digest, cwd, session ID, config directory, and expected transcript path.
- That binding deliberately records `"transport_semantic_authority": False`.
- `scripts/pty_completion_codec.py::_event_state` accepts any transcript row whose type is `assistant` and whose nested message has `stop_reason == "end_turn"`.
- `scripts/worker_execution_receipts.py` then treats the resulting `TURN_END` as provisional completion and terminates the owned process scope.

Exact bridge binding does not repair the semantic defect because the completion evidence remains a file inside a worker-writable Claude profile. Any actor that can write that JSONL can imitate the accepted row. The implementation's `transport_semantic_authority: False` is therefore accurate.

The proposed print-mode design changes the authority shape:

```text
trusted WER/broker
    -> exact signed/hash-bound Claude CLI
        -> private bounded stdout pipe: structured provider event stream
        -> tool/subagent activity serialized as nested stream messages
        -> assigned output scope: untrusted until parser-valid and closed
    -> natural CLI exit
    -> exhaustive descendant termination proof
    -> immutable stdout/output evidence
    -> deterministic replay
    -> completion receipt
```

## Recommended Plamen architecture

### 1. Introduce a typed `ClaudeStreamJsonAdapter`

The adapter should build one exact, receipt-bound launch. A representative argument shape is:

```text
claude -p
  --output-format stream-json
  --verbose
  --session-id <bound UUID>
  --model <bound model>
  --effort <bound effort>
  --permission-mode <bound policy>
  [--input-format stream-json --replay-user-messages]
```

Do not enable `--include-partial-messages` or `--forward-subagent-text` by default. They are useful for liveness or diagnostics, not for completion, and expand the byte and parser surface.

Bind in the attempt arm:

- resolved executable identity, hash, signature status, and version;
- exact argv and feature flags;
- cwd, session ID, prompt/input digest, model, effort, permission policy;
- redacted auth-route class and configuration source;
- settings, agents, MCP, plugin, and system-prompt file digests;
- stdout/stderr ceilings and JSONL line ceiling;
- output denominator and parser digests;
- platform process-tree and sandbox capability.

### 2. Make stdout the retained provider evidence

Launch the exact CLI directly with `stdout=PIPE` and `stderr=PIPE`; no PTY, terminal renderer, or session transcript observer should sit on the completion path.

The parser must:

- decode UTF-8 strictly;
- reject duplicate JSON keys, non-finite numbers, non-object rows, partial final rows, and bytes/lines beyond their ceilings;
- require one consistent `system/init` session identity;
- reject mixed session IDs and impossible event ordering;
- distinguish root messages from subagent messages using `parent_tool_use_id`;
- accept exactly one final top-level `result`;
- require `subtype == "success"`, `is_error == false`, and a completed terminal reason for the pinned protocol version;
- reject any bytes or JSON rows after `result`;
- retain and hash the exact raw stream.

Do not mint on an `assistant/end_turn` message. An assistant message ends a model step; the `result` ends the agent loop.

### 3. Require natural exit and artifact proof

Unlike the TUI, print mode exits when its query is complete. Do not kill the process when `result` appears. Continue bounded draining, require:

- root exit code 0;
- no stdout/stderr capture failure or truncation;
- owned process-tree population zero;
- normal scope closure;
- the exact assigned-output denominator present;
- every assigned file non-empty where required, within size limits, and accepted by its bound parser;
- output hashes unchanged from the post-result snapshot through final closure and replay.

The final receipt should conjunct these independent facts:

```text
PROVIDER_RESULT_OK
AND ROOT_EXIT_ZERO
AND PROCESS_SCOPE_CLOSED_ZERO
AND OUTPUT_DENOMINATOR_EXACT
AND OUTPUTS_PARSE
AND OUTPUTS_STABLE
AND STREAM_REPLAY_MATCHES
```

A forged provider row alone must never be sufficient.

### 4. Retain session JSONL only as a sidecar

Session persistence is useful for resume, audit forensics, and human inspection. Keep it under the existing leased profile if needed, but classify it as worker-influenced evidence. It may corroborate a result; it may not authorize completion, severity, or report promotion.

### 5. Treat producer exclusivity as a capability, not an assumption

Normal tool stdout is expected to be captured by Claude Code and serialized inside tool-result messages. That is substantially safer than polling a shared transcript. It still is not an official guarantee that a hostile descendant can never access the root output handle.

Use these platform policies:

- **Linux, macOS, WSL2**: enable Claude's Bash sandbox with `failIfUnavailable: true`, `allowUnsandboxedCommands: false`, a fresh process view, restrictive read/write/network rules, no unreviewed `excludedCommands`, and subprocess credential scrubbing. This strengthens the assumption but should not be described as a cryptographic channel guarantee.
- **Native Windows**: Anthropic documents no Bash sandbox. Plamen may still use provider-channel completion plus output/process proof, but must report `PRODUCER_EXCLUSIVITY_UNPROVEN_NATIVE_WINDOWS`. For a hostile-repository threat model, offer WSL2/container execution as the proof-grade path.
- **All platforms**: if the run permits arbitrary Bash or untrusted MCP processes, do not label stdout cryptographically authentic unless Plamen can prove descendants cannot obtain the producer handle.

True hostile-descendant exclusivity would require one of:

- a Claude CLI protocol that authenticates root events with a key unavailable to tools;
- a provider-owned IPC broker that emits authenticated events and never exposes its write authority to tool processes;
- tool execution under a distinct security principal with a mechanically non-inheritable/non-reopenable producer channel;
- direct server/API events plus a separately implemented tool loop, which changes authentication, cost, and Claude Code feature parity.

No reviewed official flag currently supplies that proof.

## Compatibility and trade-offs

| Requirement | CLI `-p` + `stream-json` | Agent SDK package | Existing PTY/transcript |
|---|---|---|---|
| Stored subscription OAuth | Yes, unless a higher-precedence credential exists | Not a supported third-party product assumption; docs direct developers to API/cloud auth | Yes |
| Built-in tools and MCP | Yes | Yes | Yes |
| Subagents | Yes; stream attribution available | Yes; typed attribution | Yes, but transcript authority is weak |
| Resume/session persistence | Yes | Yes | Yes |
| Programmatic multi-turn/interrupt | Yes with stream-json input; richer in SDK client | Yes | Keypress/TUI driven |
| Full terminal TUI | No | No | Yes |
| Natural machine-readable final result | Yes | Yes | No; inferred from writable JSONL |
| Removes current transcript forgery | Yes | Yes | No |
| Proves hostile-descendant writer exclusivity | No documented guarantee | No documented guarantee; same underlying local CLI transport | No |
| Local transport complexity | Low | Medium plus dependency/version lifecycle | High |

For Plamen workers, the TUI loss is favorable: it removes terminal parsing, early-kill races, renderer drift, and a writable completion oracle. The remaining feature gaps are deterministic permission handling and any genuinely interactive phase. Those should be encoded as typed control messages, not PTY heuristics.

## Fixture-first validation plan

### Offline parser and receipt fixtures

1. Valid `init -> assistant/tool cycles -> result(success)` plus valid output and exit 0 mints exactly once.
2. Missing result, multiple results, result before init, mixed session IDs, nested/subagent pseudo-result, or bytes after result produce debt.
3. Duplicate keys, `NaN`/infinity, malformed UTF-8, non-object rows, oversized line/stream, and truncated final JSONL fail closed.
4. `result` with `is_error`, any `error_*` subtype, abort/max-turn/budget terminal reason, or nonzero process exit cannot complete.
5. A root assistant `end_turn` without final result cannot complete.
6. Tool-result text containing a byte-for-byte fake `{"type":"result",...}` string remains nested escaped data and cannot become a top-level event.
7. A raw top-level forged result written by a simulated descendant is rejected unless an exclusive-producer capability is proved; native Windows records degraded provenance.
8. Valid provider result with missing, empty, oversized, extra, or parser-invalid output cannot complete.
9. Output changed after result or after root exit cannot complete.
10. Root exit with a surviving background descendant cannot complete.
11. stdout/stderr overflow, drain-thread failure, or timeout cannot complete.
12. Settings/agent/MCP/plugin files changed after arm cannot complete.
13. Auth route differs from the armed subscription/API/cloud class cannot launch.
14. `--bare` plus a required subscription route is rejected before launch.
15. Old CLI version or missing required protocol capability is rejected or explicitly downgraded; never silently accepted.
16. Resume uses the exact armed session ID and cannot cross project/profile scope.
17. Replay from immutable stdout/output blobs reproduces the same result and output digests.
18. Property/fuzz tests exercise JSONL chunking, Unicode boundaries, duplicate keys, ordering, and ceiling edges.

### Controlled official-CLI integration fixtures

Run only after explicit user approval with a dedicated test account/profile:

1. A trivial worker creates one parser-valid artifact; verify result, natural exit, process closure, and receipt replay.
2. A Bash tool prints a fake top-level result JSON string; verify it appears only inside the tool-result envelope.
3. A subagent performs work; verify `parent_tool_use_id` attribution and that only the final root result completes.
4. A background Bash task and a background subagent exercise the documented exit grace/wait behavior.
5. The session transcript is deliberately given a fake `assistant/end_turn`; verify it has no effect.
6. Resume the same session and reject a mismatched session/cwd/profile.
7. Exercise rate limit, authentication failure, interruption, timeout, and stream ceiling without producing completion.
8. Run on Linux, macOS, WSL2, and native Windows; stamp sandbox/provenance capability truthfully.

The integration corpus must keep the hostile-descendant raw-pipe injection case separate from normal tool-output nesting. Passing the latter does not prove the former.

## Implementation sequence

1. Add the strict stream parser and offline fixtures.
2. Add a headless Claude adapter behind a feature flag; dual-record PTY and stream outcomes without changing promotion.
3. Demonstrate parity for tools, subagents, sessions, outputs, timeout, and resume.
4. Make stream result plus artifact/process closure authoritative; leave transcript as sidecar.
5. Retire provisional `TURN_END` process termination.
6. Add platform provenance stamps and fail-closed sandbox policy where supported.
7. Keep PTY only as an explicitly non-proof fallback for a phase that demonstrably needs the TUI; it must not mint proof-grade completion.

This sequence is smaller and safer than trying to authenticate the current session transcript. It also simplifies Plamen's transport while retaining the legacy Claude subscription path.

## Primary official sources

- [Run Claude Code programmatically](https://code.claude.com/docs/en/headless)
- [Claude Code CLI reference](https://code.claude.com/docs/en/cli-usage)
- [Claude Code authentication and precedence](https://code.claude.com/docs/en/authentication)
- [Claude Agent SDK overview and authentication limitation](https://code.claude.com/docs/en/agent-sdk/overview)
- [Streaming output and result-message flow](https://code.claude.com/docs/en/agent-sdk/streaming-output)
- [Streaming input versus single-message mode](https://code.claude.com/docs/en/agent-sdk/streaming-vs-single-mode)
- [Agent SDK Python message and result reference](https://code.claude.com/docs/en/agent-sdk/python)
- [Sessions](https://code.claude.com/docs/en/agent-sdk/sessions)
- [Subagents](https://code.claude.com/docs/en/agent-sdk/subagents)
- [Cost and usage caveats](https://code.claude.com/docs/en/agent-sdk/cost-tracking)
- [Claude Code sandboxing and platform limits](https://code.claude.com/docs/en/sandboxing)
- [Claude Code security](https://code.claude.com/docs/en/security)

## Final disposition

**Build the stream-json headless path.** It directly closes the current completion-evidence defect, reduces PTY complexity, preserves the legacy CLI/subscription workflow, and improves deterministic replay.

**Do not claim that it alone closes hostile-descendant authenticity.** Make provider result, artifact proof, process closure, and replay a conjunction; stamp OS provenance honestly; require WSL2/container or a future authenticated provider channel for the strongest adversarial guarantee.
