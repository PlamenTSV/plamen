# Native Broker v2 Contract

Status: RED contract. Production remains fail-closed until every mandatory gate in this document passes.

Scope: the authenticated native path from `plamen_native_broker` through the static
`_plamen_native_supervisor.NativeAuthorityConsumer` into the Apple provider adapter,
Apple Container provider, POSIX supervisor, and—later—the guest-side
`PosixBackendExecution` lane. This document does not authorize a live backend,
container, credential, or audit run.

## 1. Security boundary and first production slice

The smallest production slice is one Apple/DODO **outer guest-driver lifecycle**:

1. consume one authenticated audit authority;
2. create and admit the exact stopped Apple Container guest;
3. durably start exact `container start --attach <container>`;
4. recover the same opaque process identity after a crash or lost acknowledgment;
5. wait/reap exactly once;
6. prove descendant and guest-process extinction, backend-egress revocation, and
   cleanup before deletion; and
7. bind the native terminal receipt into the supervisor terminal evidence.

This slice does not prove a complete audit. The Apple process carries the guest
driver. Codex/Claude model execution occurs inside the Linux guest and requires a
separate Linux-native `PosixBackendExecution` broker lane. Host driver output MUST
NOT be treated as an individual backend's Worker Execution Receipt (WER) output.

The current v1 broker and CPython extension are intentionally incompatible with
this contract. Production MUST remain hard-stopped until v2 exists.

## 2. Non-negotiable native custody

The following values and resources MUST remain solely in C/native-process memory
or native-owned descriptors. They MUST NOT be returned through a Python object,
callback, capsule, integer FD, buffer view, exception, log, `repr`, pickle state,
or process environment:

- both control-socket endpoints and all reconnect/rendezvous material;
- the 32-byte session HMAC key, its provisioning channel, and zeroization state;
- session ID, next sequence, last authenticated-frame digest, and replay table;
- native journal directory/lock FDs and durable CAS ownership tokens;
- retained process handles, PID-birth identity, kqueue/pidfd/process-group handles;
- executable, cwd, stdin, credential, prompt, profile, settings, MCP, CA, proxy,
  and pass-through authority FDs;
- proxy authentication and egress-control/revocation capabilities; and
- raw native authority, process, exit, extinction, or recovery tokens.

Python MAY receive immutable semantic receipt fields and bounded retained output
bytes only after the C extension has authenticated the frame, checked all bindings,
and burned the corresponding one-shot capability.

All native capability objects MUST be static, non-heap, non-subclassable,
non-constructible, creator-PID/interpreter-bound, fork-invalidated, non-copyable,
non-pickleable, and atomically single-consume. There is no production Python mint,
registry, token table, callback registrar, or generic frame-send API.

## 3. Bootstrap, authority origin, and reconnect

The production broker is one installed, unprivileged, per-user native service. On
macOS it is activated and kept by `launchd` and reached through XPC; on Linux the
same wire ABI is hosted by an admitted user service with peer credentials and
pidfds. A public service name provides discovery only and is never authority.
The broker service outlives a Python driver session and retains durable operation,
process, output, and revocation state across driver death.

The installed native launcher, broker, extension, interpreter, service manifest,
and installation receipt are one content-addressed closure. On macOS, each XPC
direction installs an exact code-signing or lightweight-code requirement before
activation. The broker additionally binds the XPC audit-token PID and process-birth
identity to a launcher registration. Failure to authenticate the installed closure,
peer, service, or platform primitive hard-stops before audit or provider effects.

The native launcher, not Python or a shell wrapper, creates the initial authority:

1. Admit the exact installed closure and requested committed audit generation.
2. Start the fixed installed Python entrypoint with
   `POSIX_SPAWN_START_SUSPENDED` on Darwin (or the equivalent admitted Linux
   primitive). No arbitrary script, module, environment, or trailing argument is
   accepted by this step.
3. While the child is suspended, register its PID, birth identity, invocation
   nonce, committed audit identity, and initial-interpreter slot with the broker
   over the mutually authenticated native service channel; make that registration
   durable.
4. Resume the child only after the broker acknowledges the exact registration.
5. During initial-interpreter module initialization, the extension asks the broker
   to burn that registration and issue exactly one audit consumer. The extension
   exposes the already-issued static object as `INITIAL_AUTHORITY`; it exposes no
   constructor, acquisition function, registry, capsule, FD, token, or callback.
6. Module reload, a second interpreter, fork, a second connection, or replay of the
   launcher registration cannot issue another consumer. Recovery uses a new native
   launcher registration explicitly bound to the existing durable audit record.

For every initial or recovery session, the extension—not Python—performs the framed
channel bootstrap:

1. Open an `AF_UNIX` connected socket pair with close-on-exec on both endpoints.
2. Generate a 32-byte session ID and independent 32-byte HMAC key with the OS CSPRNG.
3. Open a close-on-exec, one-shot anonymous key pipe.
4. Transfer the broker-side socket and key-pipe read endpoint over the authenticated
   native service channel. Raw endpoint numbers never appear in Python, argv, the
   environment, a log, or an exception.
5. The broker validates the service message's audit-token PID and birth identity
   against the unused launcher registration before accepting either descriptor.
6. Write exactly 32 key bytes, close both key-pipe endpoints as soon as their role
   completes, and zero temporary key buffers on both sides.
7. Require an authenticated `HELLO`; an unauthenticated key-bearing HELLO is invalid.

The broker and extension retain only their respective framed socket endpoint for a
session. Python never receives an accessor for either endpoint. EOF, peer-identity
change, fork, exec, malformed bootstrap, partial key transfer, or service-channel
rebind burns only that session and closes its session-owned authority FDs. It MUST
NOT kill, discard, or make retryable a durable child operation retained by the
broker. A new authenticated recovery session uses section 7's exact operation key;
it never resets or replays an effect.

## 4. Canonical frame

All integers are unsigned network byte order. Digests are raw 32-byte SHA-256.
No native struct layout, padding, host byte order, JSON, Unicode normalization, or
NUL-terminated parsing is permitted on the wire.

The v2 header is exactly 196 bytes:

| Offset | Size | Field | Required value |
|---:|---:|---|---|
| 0 | 8 | magic | `PLMBRK2\0` |
| 8 | 2 | version | `2` |
| 10 | 2 | frame type | one value from section 5 |
| 12 | 4 | flags | `0` |
| 16 | 4 | header size | `196` |
| 20 | 4 | payload size | `0..2,097,152` |
| 24 | 2 | SCM_RIGHTS FD count | `0..16` |
| 26 | 2 | reserved | `0` |
| 28 | 8 | sequence | rules below |
| 36 | 32 | session ID | exact session |
| 68 | 32 | operation nonce | exact operation or zero where specified |
| 100 | 32 | previous-frame digest | rules below |
| 132 | 32 | payload SHA-256 | exact payload digest |
| 164 | 32 | HMAC-SHA-256 | authentication tag |

The tag is `HMAC-SHA256(session_key, header[0:164] || payload)`. The authenticated
frame digest used for chaining is `SHA256(header[0:196] || payload)`.

`HELLO` has sequence zero, a zero operation nonce, and zero previous digest. The
first request has sequence one and previous digest equal to the authenticated HELLO
frame digest. Thereafter every frame increments sequence by exactly one and names
the immediately preceding authenticated frame digest. A gap, duplicate, rollback,
unknown type, nonzero reserved field, digest mismatch, tag mismatch, trailing byte,
short read, surplus FD, or missing FD irreversibly burns the session.

Across reconnects, a new session starts at sequence zero. Effect recovery is keyed
by the durable operation key in section 7, never by resetting or reusing a session.

### 4.1 Payload primitives

- `U8`, `U16`, `U32`, `U64`: fixed-width unsigned network order.
- `BOOL`: one byte, exactly `0` or `1`.
- `DIGEST`: exactly 32 bytes.
- `ID`: `U16 length || ASCII bytes`; length `1..128`, alphabet
  `[A-Za-z0-9_.:-]`, with any narrower existing identifier grammar still enforced.
- `TEXT`: `U32 length || UTF-8 bytes`; length `1..4096`, no NUL, valid shortest-form
  UTF-8, and no normalization by either peer.
- `BYTES`: `U32 length || opaque bytes`; bounded by its schema.
- `VECTOR<T>`: `U32 count || T...`; the schema supplies the maximum count.

Payloads are exact ordered tuples. Unknown, omitted, repeated, or trailing fields
are invalid. Environment entries are sorted by ASCII variable name and variable
names are unique; sorting whole `NAME=value` strings is insufficient.

## 5. Frame types and state machine

| Value | Name | Direction | Durable effect |
|---:|---|---|---|
| `0x0001` | `HELLO` | broker to extension | none |
| `0x0002` | `AUTH_CONSUME` | extension to broker | burn audit authority |
| `0x0003` | `AUTH_ACCEPTED` | broker to extension | authority consumed |
| `0x0010` | `CLI_PREPARE` | extension to broker | arm finite Apple CLI effect |
| `0x0011` | `CLI_COMMITTED` | broker to extension | finite effect/result committed |
| `0x0020` | `START_PREPARE` | extension to broker | arm start |
| `0x0021` | `STARTED` | broker to extension | process acquired and committed |
| `0x0022` | `START_RECOVER` | extension to broker | none; read exact start record |
| `0x0030` | `WAIT_PREPARE` | extension to broker | arm wait/reap |
| `0x0031` | `EXITED` | broker to extension | terminal result committed |
| `0x0032` | `WAIT_RECOVER` | extension to broker | none; read exact exit record |
| `0x0040` | `REVOKE_PREPARE` | extension to broker | arm kill/revoke/cleanup |
| `0x0041` | `REVOKED` | broker to extension | revocation/extinction committed |
| `0x00ff` | `ERROR` | either direction | terminal session failure only |

`ERROR` never proves whether an effect occurred. After an ambiguous transport error,
the caller MUST use recovery with the exact operation key; it MUST NOT retry an
effect-producing request under a new nonce.

Allowed operation transitions are:

```text
NEW -> AUTH_CONSUME -> AUTHENTICATED

AUTHENTICATED -> CLI_PREPARE -> CLI_COMMITTED -> AUTHENTICATED

AUTHENTICATED -> START_PREPARE -> START_PREPARED
START_PREPARED -> native start -> STARTED_DURABLE -> STARTED
START_PREPARED | STARTED_DURABLE -> START_RECOVER -> STARTED

STARTED -> WAIT_PREPARE -> WAIT_PREPARED
WAIT_PREPARED -> native wait/reap -> EXITED_DURABLE -> EXITED
WAIT_PREPARED | EXITED_DURABLE -> WAIT_RECOVER -> EXITED

START_PREPARED | STARTED | WAIT_PREPARED | EXITED
  -> REVOKE_PREPARE -> REVOKED_DURABLE -> REVOKED
```

No transition may return a usable Python capability before its corresponding native
journal record is durable.

## 6. Canonical operation payloads

Every request starts with this exact ordered commitment:

```text
request_fingerprint DIGEST
attempt_id ID
run_identity ID
config_sha256 DIGEST
runtime_closure_sha256 DIGEST
image_closure_sha256 DIGEST
provider_provenance_sha256 DIGEST
backend_admission_sha256 DIGEST
credential_isolation_sha256 DIGEST
egress_admission_sha256 DIGEST
```

`AUTH_CONSUME` contains only that commitment. `AUTH_ACCEPTED` repeats it and adds the
native authority-bundle digest and durable audit-authority burn checkpoint.

`CLI_PREPARE` then adds: operation kind, operation nonce, provider spec digest,
container ID/name, exact Apple CLI argv digest, empty/closed environment digest,
CLI executable content/identity/provenance digests, timeout, retained stdout/stderr
limits, observed total limits, Rosetta flag, prior provider checkpoint, and its
purpose-tagged FD roster. It is limited to the allowlisted create/inspect/resume/
delete commands required by the accepted provider; arbitrary command execution is
not an operation kind.

`START_PREPARE` then adds, in the accepted provider receipt order:

```text
container_id, spec_sha256, launch_request_sha256, launch_policy_sha256,
driver_argv_sha256, driver_environment_sha256, driver_cwd_sha256,
driver_stdin_sha256, pass_fd_roster_sha256, start_operation_nonce,
operation_sequence=1, cli_executable_sha256, provider_provenance_sha256,
rosetta_required, prior_provider_checkpoint_sha256
```

It authorizes only exact `container start --attach <bound-container>` for Apple
Container 1.3.1. Neither Python nor the request may append, reorder, or substitute
CLI flags.

`STARTED` repeats those fields and adds:

```text
native_process_id, native_process_handle_sha256, start_timestamp,
start_effect_sha256, journal_checkpoint_sha256
```

The native process handle remains opaque and C-only. Python sees at most the handle
digest inside an exact static native capability.

`WAIT_PREPARE` repeats the full start commitment and adds:

```text
start_receipt_sha256, wait_operation_nonce, operation_sequence=2,
prior_provider_checkpoint_sha256
```

`EXITED` repeats the wait commitment and adds the exact accepted provider fields:

```text
exit_code, stdout_sha256, stderr_sha256,
stdout_retained_sha256, stderr_retained_sha256,
stdout_observed_bytes, stderr_observed_bytes,
stdout_retained_bytes, stderr_retained_bytes,
stdout_truncated, stderr_truncated, start_timestamp, end_timestamp,
native_process_extinction_sha256, cleanup_sha256,
descendants_extinct=true, guest_process_extinct=true,
backend_egress_revoked=true, journal_checkpoint_sha256,
stdout_retained BYTES, stderr_retained BYTES
```

Exit code is `0..255`. Each retained stream is at most 1 MiB; each observed stream
is at most 16 MiB. Full-stream SHA-256 continues across discarded tail bytes.
`truncated` is exactly `observed_bytes != retained_bytes`. An overflow beyond the
observed bound is terminal failure followed by revocation, not a successful receipt.

`REVOKED` binds the exact start/wait operation key, process-handle digest, native
extinction digest, cleanup digest, egress-revocation evidence, and its durable
checkpoint. All three extinction/revocation booleans must be true before it can
authorize supervisor cleanup or guest deletion.

### 6.1 FD roster

Each attached FD has one purpose entry, sorted by numeric target/purpose ID:

```text
purpose U16 || target U16 || access_mode U8 || identity DIGEST
```

The receiver requires exact FD-count equality, rejects descriptor or underlying-file
aliases, sets CLOEXEC immediately, validates access mode and identity by `fstat` and
content census, and closes all FDs on every failure. Only explicitly selected child
pass FDs lose CLOEXEC during the exact spawn action.

For the Apple first slice, authority descriptors include the exact Apple CLI
executable and any native journal/working-directory descriptors. Backend prompt,
credential, profile, settings, MCP, CA, and proxy-auth FDs are not Apple CLI FDs and
MUST NOT be sent to `container`.

The later guest backend lane adds exact executable, cwd, stdin/prompt, sealed policy,
public CA, and bounded pass-FD purposes. Credential custody remains native and is
delivered only to the admitted backend process, never Python or model-tool children.

## 7. Durable effect ownership and replay

The native journal is the sole authority for whether a native effect occurred.
Provider and supervisor journals may bind native checkpoint digests but MUST NOT
infer start, wait, exit, or extinction from logs, PID existence, container state, or
Python registry contents.

The durable operation key is:

```text
SHA256(protocol-domain || request_fingerprint || attempt_id || run_identity ||
       operation_kind || operation_nonce || spec_sha256 ||
       launch_request_sha256 || prior_native_checkpoint_sha256)
```

Before any effect, the broker atomically creates and fsyncs `PREPARED`. After the
effect acquires its native process identity, it fsyncs `STARTED` before replying.
After wait/reap, it fsyncs the complete `EXITED` record—including retained stream
bytes or sealed stream-object identities—before replying. Revocation similarly
fsyncs `REVOKED` only after extinction, egress revocation, and cleanup are proven.

For an existing operation key:

- exact same request returns the already committed authenticated receipt;
- a `PREPARED` record is reconciled without repeating the effect;
- any differing byte is substitution and permanently fails that session;
- a different nonce never authorizes recovery of the old effect; and
- only the native claim owner may wait or revoke a live process.

`PREPARED` must contain enough pre-effect identity to distinguish “not started” from
“effect may have happened”. If the platform cannot resolve that ambiguity without
possible duplication, the operation hard-stops and requires native cleanup; it never
replays the effect.

Supervisor/provider order is:

```text
outer/provider ARM or CLAIM
  -> broker PREPARED (durable)
  -> native effect
  -> broker STARTED/EXITED/REVOKED (durable)
  -> authenticated acknowledgment
  -> provider commit binds broker checkpoint
  -> supervisor commit binds provider/native receipt
```

## 8. CPython and Python method mapping

`NativeAuthorityConsumer.consume_once(request_fingerprint, attempt_id)` burns before
validation and returns the exact `SupervisorAuthorities` bundle only after
`AUTH_ACCEPTED`. Each bundle member is a static native-backed authority object.

The provider member implements the existing `ProviderLifecycle` methods:

| Supervisor method | Adapter/provider request | Broker operation |
|---|---|---|
| `create_stopped` | exact ten-mount `ContainerSpec` and lower recensus | `CLI_PREPARE/CLI_COMMITTED` |
| `inspect_stopped` | exact created receipt/spec | finite authenticated inspect |
| `resume_guest` | exact request/created identity | finite admitted operation |
| `start_driver` | exact `DriverLaunchRequest` | `START_PREPARE/STARTED` |
| `wait_driver` | exact start receipt and wait ticket | `WAIT_PREPARE/EXITED` |
| `delete_guest` | exact terminal extinction/delete request | finite delete after `REVOKED` |

The production Apple adapter may perform deterministic translation only after an
exact native capability has been consumed. The native authority independently
recomputes and compares every commitment; Python dataclasses never establish
authority. The current TEST_ONLY provider callback and receipt registries remain
structurally unreachable from production.

The extension also exposes only opaque exact types for the live process and terminal
receipt. It exposes no `fileno`, PID-only constructor, token string, registry key,
socket accessor, raw frame parser, or callback installation method.

For the later guest backend lane, native execution must implement the accepted
`PosixBackendExecution` lifecycle—preview binding, materialize after WER inner arm,
immediate pre-create revalidation, process-created transition, and terminal
revocation—without exposing executable credentials, environment secrets, or
authority FDs to Python. The present Python production hard-stop stays in place
until that separate lane passes its gates.

## 9. Receipt mapping

An authenticated native `STARTED` receipt maps exactly to
`apple_container_provider.DriverStartReceipt`; its opaque static process capability
travels with `DriverStartResult`. The adapter maps the same commitment to the
supervisor `DriverStartReceipt` without changing attempt, guest, launch, process, or
checkpoint identity.

An authenticated native `EXITED` receipt maps exactly to
`apple_container_provider.DriverWaitReceipt/DriverWaitResult`. The adapter maps it
to supervisor `DriverExitReceipt` as follows:

- `attempt_id`: unchanged native/provider audit attempt;
- `guest_id`: exact admitted container/guest identity;
- `launch_sha256`: exact supervisor driver-launch digest already bound by start;
- `exit_code`: unchanged native exit code; and
- `wait_sha256`: SHA-256 of the complete authenticated native `EXITED` frame.

The provider, adapter, and supervisor may wrap these values in their existing frozen
dataclasses, but only the retained static native authority may validate/consume the
underlying receipt. No Python bytes/dict/dataclass can mint a native completion.

The Apple terminal receipt authenticates the outer guest-driver process. WER evidence
inside the guest remains a separately authenticated artifact. Once the Linux-native
backend lane exists, its native terminal receipt supplies the exact bounded backend
stdout/stderr to WER; WER must still independently validate and replay stream-JSON.

## 10. Mandatory RED gates

These exact gate names are reserved. Every gate must first demonstrate failure
against a missing or deliberately defective implementation and then pass the final
candidate.

### Protocol and bootstrap

- `RED_BROKER_V2_ABI_CONSTANT_EQUALITY`
- `RED_BROKER_V2_AUTHENTICATED_HELLO_ONLY`
- `RED_BROKER_V2_SESSION_KEY_NEVER_PYTHON_VISIBLE`
- `RED_BROKER_V2_FORGED_PEER_EXECUTABLE_REJECTED`
- `RED_BROKER_V2_TRUNCATED_OVERSIZE_TRAILING_FRAME_REJECTED`
- `RED_BROKER_V2_HMAC_PAYLOAD_AND_HEADER_FORGERY_REJECTED`
- `RED_BROKER_V2_SEQUENCE_GAP_ROLLBACK_AND_CHAIN_REPLAY_REJECTED`
- `RED_BROKER_V2_CROSS_SESSION_ATTEMPT_AND_NONCE_REPLAY_REJECTED`

### FD and process custody

- `RED_BROKER_V2_SCM_RIGHTS_COUNT_ORDER_AND_PURPOSE_EXACT`
- `RED_BROKER_V2_FD_ALIAS_ACCESS_MODE_AND_IDENTITY_REJECTED`
- `RED_BROKER_V2_CLOEXEC_AND_FAILURE_PREFIX_FD_CLOSURE`
- `RED_BROKER_V2_NO_SECRET_ARGV_ENV_REPR_PICKLE_OR_EXCEPTION`
- `RED_BROKER_V2_CREATOR_PID_FORK_AND_SUBINTERPRETER_REJECTED`
- `RED_BROKER_V2_TWO_THREAD_SINGLE_CONSUME`
- `RED_BROKER_V2_PID_BIRTH_REUSE_REJECTED`

### Durable effects and recovery

- `RED_BROKER_V2_START_PREPARE_BEFORE_EFFECT`
- `RED_BROKER_V2_START_ACK_LOSS_RECOVERS_WITHOUT_DUPLICATE`
- `RED_BROKER_V2_CROSS_PROCESS_START_RACE_EXACTLY_ONCE`
- `RED_BROKER_V2_WAIT_PREPARE_BEFORE_REAP`
- `RED_BROKER_V2_WAIT_ACK_LOSS_RECOVERS_IDENTICAL_EXIT`
- `RED_BROKER_V2_CROSS_PROCESS_WAIT_RACE_EXACTLY_ONCE`
- `RED_BROKER_V2_CLAIM_LOSER_CANNOT_WAIT_OR_REVOKE`
- `RED_BROKER_V2_PARENT_DEATH_DURABLE_RECONNECT`
- `RED_BROKER_V2_AMBIGUOUS_PREPARE_NEVER_REPEATS_EFFECT`
- `RED_BROKER_V2_REVOCATION_PRECEDES_CLEANUP_COMMIT`

### Apple lifecycle

- `RED_BROKER_V2_APPLE_CONTAINER_1_3_1_IDENTITY_EXACT`
- `RED_BROKER_V2_APPLE_CLI_PATH_DESCRIPTOR_SUBSTITUTION_REJECTED`
- `RED_BROKER_V2_START_ATTACH_ARGV_EXACT`
- `RED_BROKER_V2_ROSETTA_DODO_ONLY_BINDING_EXACT`
- `RED_BROKER_V2_TEN_MOUNT_PURPOSE_ROSTER_EXACT`
- `RED_BROKER_V2_LOWER_MERGED_RECENSUS_DRIFT_REJECTED`
- `RED_BROKER_V2_TIMEOUT_SIGNAL_AND_OUTPUT_OVERFLOW_REVOKE`
- `RED_BROKER_V2_STREAM_FULL_RETAINED_DIGEST_AND_LENGTH_EXACT`
- `RED_BROKER_V2_DESCENDANTS_GUEST_AND_EGRESS_EXTINCT_BEFORE_DELETE`

### Extension, adapter, supervisor, and WER

- `RED_NATIVE_CONSUMER_EXTENSION_ORIGIN_AND_STATIC_TYPE_EXACT`
- `RED_NATIVE_CONSUMER_NO_PRODUCTION_MINT_REGISTRY_OR_FACTORY`
- `RED_NATIVE_CONSUMER_WRONG_FINGERPRINT_BURNS_ONCE`
- `RED_NATIVE_PROCESS_AND_EXIT_CAPABILITY_OBJECT_NEW_REJECTED`
- `RED_APPLE_ADAPTER_MISSING_EXTRA_DUPLICATE_REORDER_ALIAS_REJECTED`
- `RED_APPLE_PROVIDER_TEST_ONLY_AUTHORITY_CANNOT_CROSS_PRODUCTION`
- `RED_SUPERVISOR_NATIVE_START_WAIT_RECEIPT_BINDING_EXACT`
- `RED_SUPERVISOR_CRASH_RECOVERY_NEVER_REPEATS_NATIVE_EFFECT`
- `RED_WER_REJECTS_APPLE_DRIVER_OUTPUT_AS_BACKEND_OUTPUT`
- `RED_POSIX_BACKEND_EXECUTION_REMAINS_HARDSTOP_UNTIL_LINUX_NATIVE`

### Release gates

- `RED_DODO_CREDENTIAL_FREE_OUTER_DRIVER_SMOKE`
- `RED_DODO_GUEST_NATIVE_BACKEND_STREAM_REPLAY`
- `RED_DODO_CREDENTIAL_BEARING_END_TO_END`

The last three gates run in order. Failure or absence of any earlier mandatory gate
forbids the first smoke. The credential-bearing gate remains forbidden until the
guest-side native backend lane proves credential custody and descendant no-read.

## 11. Required implementation order

1. Broker v2 wire, durable journal, Apple finite/start/wait/recover/revoke operations,
   production builder, provenance manifest, and native tests.
2. CPython extension v2 parser/session plus static native authority/process/exit
   types and C-only acquisition.
3. Apple provider production interface migration away from Python authority/receipt
   registries; TEST_ONLY remains type-separated.
4. Apple supervisor adapter production translation using the exact native authority.
5. POSIX supervisor authority-bundle and native receipt integration.
6. Separate Linux guest broker plus native `PosixBackendExecution`/WER lane.
7. DODO composition and the ordered release gates above.

No later step may simulate an earlier native authority with Python data. Until its
step and RED gates are complete, the corresponding production entry point must
raise its typed unavailability error before inspecting arguments or invoking any
callback, importer, filesystem accessor, provider, or process API.
