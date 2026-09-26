# Plamen v3 durable decisions

These decisions constrain implementation and supersession. Changing one requires
a reviewed replacement decision, an old-to-new invariant crosswalk, and evidence
that no security or operational scope was lost.

## Authority architecture

1. **Do not revive the big-bang SQLite ledger.** The database-first event/finding
   design is superseded by domain-typed immutable JSON authorities, PhaseIO,
   semantic journals, CAS-bound worker incorporation, exact reconciliation, and
   explicit projections.
2. **One normative owner per concern.** Shared authority and disposition belong
   to the method-application RFC; provider facts to the ecosystem contract;
   method content to MethodCards; worker lifecycle to the scheduler; evaluation
   governance to the evaluation plan.
3. **Markdown and disk markers are projections or transport evidence.** They are
   never universal semantic or execution authority.
4. **Stable identities are not display IDs.** Content, source, premise, work,
   attempt, evidence, alias, route, and report identities remain exact and
   digest-bound across transformations.

## Methodology and negative authority

5. **MethodCards are the sole normative method-content catalog.** Prompts,
   skills, and verifier registries reference versioned cards instead of creating
   competing method definitions.
6. **Program Facts and graphs are additive evidence.** Capability-limited,
   incomplete, stale, or failed facts may add candidates or disagreement; they
   cannot authorize a negative, demotion, clean receipt, or safe conclusion.
7. **Adaptive attention follows exact coverage debt.** Static blanket agent-count
   increases are not a substitute. Program Facts and attention policy remain
   separate mechanisms and future experimental factors.
8. **Terminal negatives require independent authority.** Model confidence,
   bounded search, failed tooling, precedent, trust tags, provider declarations,
   or missing output cannot close a candidate by themselves.
9. **Reports are projections.** Report agents cannot mint, delete, silently omit,
   rerate, or legitimize unsupported dispositions. Verification precedes report
   authority.

### August research constraints

- **Rule 0: enumerate mechanically, decide semantically.** Python must enumerate
  every mechanically discoverable obligation. LLM workers receive bounded
  shards of about five rows only when disposition requires protocol intent;
  merged results reconcile exactly against the full worklist.
- **A zero scan is dead instrumentation, not a clean result.** Every mechanical
  deriver emits `sites_scanned` and `candidates_emitted`, and every harvesting
  gate has a real producer-output fixture plus a non-zero assertion where work
  was expected.
- **Fuzz and symbolic PASS are not favorable security evidence.** Only an
  authenticated counterexample may raise evidence strength. Mutation may test
  invariant vacuity or deriver liveness, but may not stand in for a recall
  benchmark.
- **Research confidence is preserved.** `CONFIRMED` work may proceed against the
  current tree; `REPORTED` is reverified before action; `VERIFY-FIRST` is
  rederived before code changes; `INFERRED` remains a hypothesis.
- **Improvement must replace legacy complexity.** The reviewed change had added
  about 370,000 lines with none removed, enlarged three god-functions, and left
  24 modules / 39,824 lines unreachable. Each P-item deletes or replaces its
  legacy counterpart; driver size and god-function length do not increase
  without a separately reviewed exception.

### Do not build

The August decision layer rejects these attractive but unsupported expansions:

- mutation as a recall benchmark (mutation remains allowed for vacuity and
  positive-control checks);
- the Certora AutoProver agent layer;
- a standalone symbolic-execution dependency instead of the narrow Foundry
  refutation lane;
- fan-out-then-debate on one question (parallel scope partition and bounded
  worklist sharding remain required);
- prompt-only “double-check” scaffolding;
- an SMTChecker migration.

## Orchestration and execution

10. **The Python V2 driver solely sequences audit phases.** Do not manually
    orchestrate recon, breadth, depth, verification, or report phases.
11. **Instantiate templates; do not inject replacement methodology.** Workers
    read their complete versioned prompt/methodology resources.
12. **File presence is not completion.** A worker result becomes authoritative
    only after immutable input binding, owned execution closure, semantic
    validation, exact output-prestate/CAS checks, and parent incorporation.
13. **Failure remains debt.** Missing, malformed, stale, capped, timed-out,
    unsupported, inaccessible, or ambiguous work cannot be translated to clean
    absence or silent phase success.
14. **Retry and resume preserve generation identity.** A retry cannot reuse
    mismatched route or inputs; resume mismatch stops before mutation unless a
    distinct-destination migration is explicitly authorized.

## Backend and platform behavior

15. **Claude and Codex share logical denominators and authority semantics.** PTY,
    direct-exec, MCP availability, sandboxing, and OS primitives may differ, but
    completion, fallback, debt, and evidence meaning do not.
16. **Requested route is not actual route.** Backend, model, effort, service
    tier, fallback, and terminal provider outcome are observed and recorded. An
    unobservable result is `UNKNOWN_BLOCKED`, never inferred from the command.
17. **Fallback changes are explicit generations.** Capacity, authentication,
    safety, or availability fallback cannot silently substitute a semantic tier.
18. **Cross-platform differences are adapters.** Windows Job Objects and POSIX
    process/session primitives implement one lifecycle contract; platform
    variance cannot weaken it.
19. **Current production installation is Windows-only.** The macOS bootstrap is
    source-development support, not native runtime proof. Linux and macOS become
    supported only after a POSIX dispatcher plus keeper/recovery adapter passes
    clean install, start, stop, crash recovery, and resume validation. Until
    then, public commands fail explicitly before mutation on those platforms.

## Packaging and storage

20. **The repository is the editable source of truth.** Installed trees,
    development checkouts, caches, and packaged runtimes are distinct. Installed
    bytes are immutable and receipt-bound.
21. **Generated audit artifacts never enter the canonical target checkout or
    the audited source denominator.** The public driver keeps its mandatory
    `.scratchpad` below `PROJECT_ROOT`, so release E2Es use a fresh disposable
    audit clone under an owned work root. The canonical checkout remains clean;
    native execution mounts the frozen source lower read-only; `.scratchpad`
    and report/export paths are excluded from source authority and have explicit
    retention and cleanup.
22. **Bound both returned data and backing storage.** Tail truncation does not
    satisfy a spool quota. Logs, transcripts, ledgers, and temporary files need
    explicit capacity and lifecycle policies.
23. **Cleanup evidence is reference-bound.** Age or terminal state alone is not
    deletion authority. Retention changes preserve exact replay, parent/path
    semantics, concurrent readers, crash recovery, and rollback.

## Evaluation and privacy

24. **Ground truth and the neutral evaluator remain out of tree.** The public
    branch contains interfaces, schemas, and blinded export support, not private
    answers or evaluator control.
25. **Benchmarking is deferred, not deleted.** This goal validates the improved
    tool. Comparative recall, precision, report-quality, and cost benchmarking
    against old Plamen happens later under a separate goal.
26. **Runtime E2E audits are validation, not benchmarking.** They may exercise
    the tool without exposing or scoring against grader-only ground truth.
27. **Lock selection requires a unique manifest-consistent authority.** This
    supersedes the earlier DODO-specific `AMBIGUOUS_JS_LOCKS` decision after the
    schema-v2 lock evaluator proved a content-bound distinction without target
    edits or repository-history inference. DODO's `yarn.lock` is recursively
    manifest-consistent (1,065 reachable stanzas, zero unused; 1,386 exact
    selector-to-resolution rows), while `package-lock.json` is rejected with
    `NPM_ROOT_DEPENDENCIES_MISMATCH` and
    `NPM_ROOT_DEVDEPENDENCIES_MISMATCH`. The receipt retains both candidate
    assessments and binds `selection_basis=UNIQUE_MANIFEST_CONSISTENT_LOCK`;
    its selection digest is
    `ac0301185fb20f98aeee75ed596c7801ef06f83eb0d7a8ed360588da65819c69`.
    Zero or multiple manifest-consistent candidates remain typed ambiguity.
28. **POSIX production audits run the existing driver inside a Linux guest.**
    The Python driver remains the sole phase sequencer. macOS uses an Apple
    container VM provider; native Linux uses an OCI/cgroup-v2 provider. Both
    providers implement the same attempt, admission, lifecycle, export, and
    resume receipts instead of introducing a second audit engine.
29. **The audit target is immutable input, not the worker filesystem.** The host
    checkout is mounted read-only as an overlay lower directory. Each attempt
    receives private upper/work/merged directories, a separate owned
    scratchpad, and componentwise identity checks. Reports return only through
    the governed export boundary after the guest process tree is extinct.
30. **Apple `container --internal` is not accepted as credential isolation.**
    Apple Container 1.3.1 reports this network mode as exact `hostOnly`. A
    supported runtime must prove its exact network and egress posture and
    provide only a narrow, attempt-owned backend channel. DNS suppression,
    network naming, or documentation descriptions do not replace runtime
    evidence. Admission requires a bounded direct-IP negative challenge, a
    host-gateway bypass challenge, and separate attempt-authenticated proxy
    evidence; success of any one check cannot clear the others. Until that
    proof exists, a credential-bearing audit fails before launch.
31. **Runtime images are built from a sealed, offline content closure.** Apple
    `container build` exposes cache and pull controls but no enforceable
    build-network-off switch, so it is not the authority for the production
    image. Plamen emits a deterministic OCI Image Layout directly from the
    externally authenticated lock and its one-shot bounded readers. The image
    may be loaded only without a force/repair flag and must be inspected back to
    the expected manifest, config, layer, platform, user, rootfs, entrypoint,
    SBOM, and runtime-census digests before use.
32. **Repository instructions and settings are audit data, not worker policy.**
    Backend CLIs start from a trusted control directory outside the target and
    receive the project as an explicit working directory, so target-owned
    `AGENTS.md`, `CLAUDE.md`, settings, hooks, plugins, MCP declarations, and
    exec policies are not auto-loaded as authority. Codex uses an otherwise
    empty private `CODEX_HOME`, an exact named request-bound permission profile,
    and an authenticated census proving that no base configuration or extra
    files exist. Because Codex `0.152.0` has no independent
    `--ignore-project-config` switch, every trusted control-directory ancestor
    is also recensused to prove `.codex/config.toml` absent. Claude uses its
    sealed invocation settings, treats sandbox unavailability as fatal, and
    has no unsandboxed escape hatch. Backend subprocesses may write only the
    overlay workspace and owned scratch roots and may not read the credential
    root.
33. **Legacy backend sandbox mode does not isolate backend credentials.**
    Codex `workspace-write` constrains writes and network but permits spawned
    commands to read files, so a materialized `CODEX_HOME/auth.json` inside the
    same readable guest namespace is not a production credential boundary.
    Codex production launch instead uses a sealed permission profile supported
    by the exact pinned CLI: deny `:root`, reopen only `:minimal` for read and
    the explicit audit workspace roots for write, keep command network disabled,
    and prove that the credential root is unreadable in a real macOS/Linux
    sandbox before releasing credentials.  The legacy `--sandbox` settings may
    not be mixed into that launch because they override permission profiles.
    Claude must establish the same no-read/no-inheritance outcome using its
    sealed restricted-sandbox settings.  A pinned native/out-of-process broker
    remains mandatory wherever either CLI cannot enforce the split policy.
    Python credential acquisition remains synthetic/non-production until that
    enforcement and the descriptor-native Darwin metadata verifier are proven.
34. **Backend egress is verified CONNECT passthrough, not TLS interception.**
    Terminating backend TLS would expose bearer material and payloads to a new
    proxy trust domain.  Plamen instead permits a non-terminating,
    attempt-authenticated `VERIFIED_CONNECT_ALLOWLIST` only when the backend
    executable/version/digest is pinned, all optional backend network surfaces
    are disabled, and model-generated commands have independently proven zero
    network access.  The proxy admits exact backend host/port authorities,
    rejects IP literals/private resolutions/rebinding, binds observed DNS and
    provider network evidence, and publishes the opaque-TLS/domain-fronting
    limitation as typed assurance debt.  A sealed public CA bundle remains a
    backend TLS input; it is not a private interception CA.  If any backend can
    originate arbitrary destinations or the command-network proof fails, audit
    launch is refused rather than widening this channel.
35. **The sealed supervisor is trusted code; Python object opacity is not a
    hostile same-process security boundary.** Capability registries and
    one-shot objects prevent accidental rebinding inside the reviewed
    supervisor, but they do not claim resistance to reflection or arbitrary
    code already executing in that interpreter. Target-controlled bytes and
    model-generated commands therefore execute only in separately constrained
    processes inside the admitted guest. Facts about executable identity,
    mounted objects, process-tree extinction, provider state, durable replay,
    and credential custody must come from descriptor-bound native or
    out-of-process authorities and be authenticated back to the supervisor.
    Same-process test doubles may prove Python control flow, never those native
    facts.
36. **POSIX audit dispatch occurs before host bootstrap and only for exact
    audit routes.** The host frontend may normalize and dispatch noninteractive
    SC/L1 start, `start-config`, and `resume` requests to one governed guest
    supervisor. It may not create the target scratchpad or run audit phases on
    the host. Help, version, plan, detection, and doctor remain read-only host
    routes; install, setup, migrate, uninstall, RAG, compare, and private
    mutators continue to refuse until each has its own POSIX transaction and
    recovery contract. No environment variable or command-line token is a
    runtime-capability bypass.
37. **Outer guest isolation does not replace inner backend launch policy.**
    Every POSIX Codex or Claude leaf must consume the sealed backend launch
    plan at the final process-creation boundary. Codex's historical
    `--dangerously-bypass-approvals-and-sandbox` path is forbidden on POSIX,
    including retry, severity-adjudication, and auxiliary worker routes. The
    final physical argv, environment, working directory, credentials, profile
    or settings, egress authority, retained descriptors, process scope, and
    completion receipt are one attempt-bound authority. Windows keeps its
    current qualified adapter until a separately reviewed unification proves
    parity.
38. **The driver sees the overlay, never the immutable host target.** Inside a
    guest, `project_root` is the writable merged overlay used as the driver's
    working directory and report destination, while the owned scratch root is
    a separate mount. The host checkout remains a read-only lower input.
    Host-absolute documentation and scope inputs require explicit read-only
    mount mappings. Only allowlisted artifacts are exported after process-tree
    extinction; resume reconstructs the same guest identities instead of
    writing directly into the host repository.
39. **Apple runtime installation is an explicit, provenance-bound host action.**
    Plamen may stage and verify the signed/notarized Apple `container` 1.3.1
    installer, but an audit command may not silently install it, start its
    services, download a kernel, or widen system configuration. Production
    admission binds the exact package hash and signer, the full 1.3.1 release
    commit, the installed CLI/API-server/plugin binary identities and digests,
    and the separately pinned kernel/runtime closure. The installer package's
    version string or a short reported commit is insufficient authority.
40. **The first POSIX release keeps the already-reviewed backend envelopes.**
    The production and DODO E2E image pins Codex `0.152.0` and Claude
    `2.1.252`. Later staged binaries are candidates for a separate semantic,
    provenance, and confinement review; their availability is not authority to
    upgrade the runtime closure. Every request, launch attempt, executable
    receipt, backend output parser, and image manifest binds the selected
    version and executable digest.
41. **Claude's POSIX native sandbox is a distinct semantic policy lane.** The
    legacy restricted-analysis overlay requires a hook-based `default` mode
    and remains valid only for its qualified platform path. A governed Linux
    guest instead binds Claude `2.1.252` native sandbox settings with
    `--permission-mode dontAsk`, rejects hooks/plugins and unsandboxed escape
    flags, and treats sandbox unavailability as fatal. The two settings schemas
    may not be silently translated or accepted by the same validator.
42. **A sealed backend profile must be proven active, not merely named.** For
    Codex `0.152.0`, `--profile <name>` loads
    `$CODEX_HOME/<name>.config.toml`, but `--ignore-user-config` also suppresses
    that selected file. Those flags are therefore forbidden together. The
    accepted launch must bind an exact private-home census (including base
    config absence), use `--strict-config`, select the sealed profile, and
    prove the resulting active permission profile at the descendant sandbox
    boundary. Static tagged-source evidence supports the path; a packaged
    Linux guest conformance receipt remains mandatory before credentials are
    released.
43. **The guest image has one complete, explicit final root filesystem.** Its
    OCI parent is the fixed empty-root sentinel, not an inherited distribution
    image whose unseen layers are trusted by reference. An authenticated
    complete-rootfs archive and provenance document, a separate Plamen runtime
    closure, CPython, exact backend binaries, and toolchain assets are expanded
    into one deterministic final scratch-root layer. The image manifest,
    config, DiffID, SBOM, runtime census, and rootfs provenance cross-bind those
    bytes; a missing complete root or authenticated one-shot consumer is a
    production hardstop.
44. **Python cannot issue production verification authority.** A module-private
    sentinel, registry, token, exact Python type, frozen dataclass, or one-shot
    object is not a security boundary against same-process introspection. The
    production launch, release, context, and supervisor consumers therefore
    accept only authenticated native or out-of-process capabilities and remain
    hard-stopped until those capabilities exist. Structural tests use visibly
    distinct `TEST_ONLY` issuers, schemas, statuses, and types that production
    consumers reject. Native facts may be projected into Python for control
    flow, but no Python callback or mutable registry may mint or upgrade them.
45. **Supervisor guest admission is an exact ten-mount protocol.** The legacy
    three-mount OCI admission receipt cannot authorize a supervised audit. The
    admitted guest contains writable `project-merged`, `scratch`, and `state`
    mounts plus read-only `control`, `seccomp`, `credentials`,
    `backend-context`, `runtime`, `docs`, and `scope` mounts at their fixed
    paths. The immutable host target remains a separately authenticated,
    read-only overlay lower and is bound into the merged-project proof. Missing,
    extra, reordered, aliased, or cross-role descriptor bindings fail closed.
46. **DODO's Solidity compiler uses an explicit architecture lane.** The target
    pins Solidity `0.8.26`, for which the official Solidity distribution has no
    Linux ARM64 native binary. Plamen binds the official Linux AMD64 compiler
    SHA-256
    `d5f23436f443edb85d8e76906d12f0a86ce0490e7663a9e608efeb7a93f149ef`.
    Apple Silicon may use those bytes only through a request-bound,
    admitted Apple Container `--rosetta` lane with the exact compatibility
    closure; Rosetta is not enabled globally. Other ARM64 Linux providers fail
    with typed compiler-unavailable evidence unless an authenticated emulation
    or reproducible native-build lane is separately approved. `solc-js` and
    unofficial ARM64 builds are never silent substitutes.
47. **A missing native process authority is rejected before Python inspects the
    request.** On POSIX, every production backend and installed-front launch
    entrypoint raises its typed native-authority error before creating a
    directory, lock, blob, journal entry, or child process and before reading,
    hashing, comparing, coercing, or dispatching on caller-supplied Python
    values. Explicit argument deletion is also forbidden before the hardstop,
    because reference-count finalizers are dynamic callbacks. TEST_ONLY launch
    state binds its creator process and interpreter, is invalidated after fork,
    and serializes each preview, materialization, pre-create validation,
    creation, completion, and abort transition exactly once.
48. **Physical-process evidence binds the complete effect, not only argv.** A
    launch authority and its completion must cross-bind the exact executable
    descriptor and identity, ordered argv, complete environment key/value set,
    working-directory descriptor, stdin identity, passed-descriptor roster and
    count, containment, exit status, bounded retained output, full output
    digests, and process-tree extinction. Python dataclasses and success
    booleans cannot authenticate those facts. Provider start and wait effects
    require an atomic native or durable claim before invocation so two provider
    instances cannot consume the same armed transition.
49. **Path verification hands off a retained capability, not a pathname
    claim.** Rechecking a path, leaf inode, or ancestry immediately before a
    Python function returns cannot prove what a later caller opens; a parent
    may be renamed after the final check. OCI layouts, archives, artifacts, and
    build products therefore remain descriptor- or native-handle-bound through
    their next consuming effect. Cleanup may remove only the exact retained
    identity it created and never recursively follows a substituted published
    name. APIs that return an authoritative pathname without an atomic native
    handoff stay production-hard-stopped.
50. **Native builds bind an immutable, descriptor-addressed input and output
    closure.** The build key and manifest include the builder, interpreter,
    compiler and transitive helpers, exact argv and copied environment, Python
    headers, compiler resource headers, SDK headers and libraries, canonical
    extension basename, and their directory topology. Owner-clearable file
    flags plus post-build hashing do not prevent ABA. Compilation and
    publication use sealed or separately protected retained objects, followed
    by full stat and content replay after publication and final durability;
    production and TEST_ONLY modules retain distinct init symbols, basenames,
    schemas, and packaging authority.
51. **The first supported Apple host closure is exact, not version-range
    compatible.** The admitted Apple Container package is
    `com.apple.container-installer` 1.3.1 at upstream commit
    `a9a62e28f6beb88940122a3d7b286f2d5ae8053a`, signed by team
    `UPBK2H6LZM`; the installed CLI SHA-256 is
    `c6f8ef172248f7b8a30fa3e502359bba678bc993991c37b848dbead1914e86b1`.
    The exact same-team runtime closure additionally binds the API server
    (`ace7e2200c4302b7184e29f4063d346305869202c8bda794eaae0613e39f79e2`),
    core-images plugin
    (`89bd502b4c914a08dbca68350dbf6bad331acc510e9b83245f757a583cc388fc`),
    vmnet plugin
    (`fcc48b3c1f393025df004de378704d69db7d06da9695ec44f291b8b2a65dd8f3`),
    Linux runtime plugin
    (`9528b7c70f5f84a3318ed5616d20bd5247af9672502cae6278f6ea52b2d69369`),
    and machine API server
    (`94424e93d4a0f10cfcf6297d7d1d5a302eebc789b1c9449df2250062cb912659`).
    The Kata 3.32.0 archive SHA-256 is
    `8736c054d9223974735394f822000823baef509e1c33405ec798240fa9b6e4b5`
    and the selected `vmlinux-6.18.35-197-debug` member SHA-256 is
    `fb2cfb79eb1ae19447a85d75682d7fa5cfec97e24beb2609a492b806e8072c8d`.
    A version banner or configured archive digest alone does not authenticate
    the installed member used by a VM.
52. **Apple's default init image tag is never an audit authority.** Every
    admitted create request supplies the immutable
    `ghcr.io/apple/containerization/vminit` OCI index digest
    `sha256:cde8a93f9861c664bf2b74b4e2893cf877680806f12e7e989eb9c51b2f2e93bf`
    and binds its Linux ARM64 manifest digest
    `sha256:71f6c228becbb32398ee44b8569249524722c2e11030f61cc7a5673695e5a422`.
    The configured `0.42.0` tag may be provenance evidence, but it is not used
    as the runtime selector and cannot silently trigger a mutable pull.
53. **A credential-free guest smoke proves only the container substrate.** A
    successful non-root, read-only, capability-dropped `/bin/true` lifecycle
    with the exact kernel, init image, and base-image manifest proves that the
    Apple API server can create, start, reap, and remove a Linux guest. It is
    not a Plamen audit and cannot satisfy native broker, credential isolation,
    backend WER, phase-gate, or DODO E2E release evidence.
54. **Apple `hostOnly` is topology evidence, not proxy-only enforcement.** A
    credential-free live challenge on the exact admitted Apple Container
    runtime proved that a guest on an `--internal` network could connect to a
    deliberately opened arbitrary TCP listener on the network gateway. Plamen
    therefore rejects `hostOnly` by itself as backend-egress admission. Before
    any credential release, the native authority must install and authenticate
    an attempt-scoped rule set that denies direct public IPv4/IPv6 traffic and
    every host-gateway path except the exact authenticated CONNECT proxy, then
    bind independent direct-IP, other-gateway-port, missing-auth, wrong-auth,
    and cross-attempt-auth challenges into the durable admission receipt.
    Teardown must prove proxy, relay, rule-set, guest-attachment, and network
    extinction; success booleans or one negative public-IP probe are
    insufficient.
55. **The POSIX broker is a durable native service, not a Python child.** A
    per-session broker spawned by the audit interpreter cannot both die with
    that interpreter and retain authoritative process/output state for crash
    recovery. The unified v2 ABI therefore uses one installed, unprivileged
    per-user service (`launchd`/XPC on macOS and an admitted peer-credential
    service on Linux). A fixed native launcher registers an exact suspended
    Python PID/birth and committed audit generation before Python runs; module
    initialization burns that registration and publishes one pre-issued static
    `INITIAL_AUTHORITY`. The extension creates fresh framed socket/key sessions
    and hands the broker endpoints through the authenticated native service
    channel. Python exposes no authority factory, socket, key, FD, token, or
    callback, and driver death burns a session without killing or making
    retryable a durable broker-owned effect.
56. **Independent semantic review uses the raw valid producer-delivery
    denominator.** P0-B requires application completeness to remain orthogonal
    to semantic outcome. Therefore every schema-valid producer row whose
    `disposition` is `DELIVERED` receives independent review even when its
    reconciled write-site/semantic status is `DEFERRED` or its typed sources
    conflict. Producer uncertainty cannot remove a row from the independent
    denominator. Missing, malformed, duplicate, or foreign rows are repaired
    before this boundary and grant no review authority; final reconciliation
    still preserves conflict and unresolved debt unless independent evidence
    validly closes it.

## Historical corrections

- The July observation that seven named architecture artifacts were absent is
  superseded by their current presence. Presence does not prove semantic
  completeness or runtime reachability.
- The failed private-target p18 run is sealed failure evidence. Its staged output must not
  be repaired in place or presented as a completed audit.
- Scoped green tests remain scoped. No test count, phase gate, source hash, or
  generated report expands into whole-tool acceptance without its required
  package, backend, platform, fault, and E2E evidence.
- The earlier claim that producer output caps were the highest-leverage recall
  fix is corrected: measured caps were non-binding, while under-enumeration was
  dominant. Severity-prioritization language still goes; Rule 0 is the repair.
- Off-by-one analysis is already owned by the Validation Sweep; its observed
  failure is delivery/enumeration, not an absent method class.
- Narrowing-cast coverage is not globally absent. It exists in four non-EVM
  ecosystems; the verified gap is specifically total in EVM.
- The P-14 prototype was cheap and discriminating but did not prove a missed
  real bug, and one target produced 81 obligations against a historical cap of
  15. Treat it as throwaway evidence, not production implementation.
