# Codex-native deterministic-driver wizard

1. Resolve the target to an absolute path and inspect it read-only for an
   existing `.scratchpad/config.json` and `_v2_checkpoint.json`.
2. If an existing config is present, never rewrite it. Resume it with:

   ```text
   plamen resume "{CONFIG_PATH}"
   ```

3. A new audit requires a distinct clean destination. Never delete, move,
   rename, archive, or overwrite an existing scratchpad to make room.
4. Collect only missing values: mode (`light`, `core`, `thorough`), target,
   optional docs, optional scope, and `proven_only` (default false).
5. Write valid JSON to `{PROJECT_ROOT}/.scratchpad/config.json`, then launch
   exactly one shared driver process. Do not orchestrate phases or spawn audit
   agents yourself.
6. For a new run launch with explicit intent:

   ```text
   plamen start-config "{CONFIG_PATH}"
   ```

   This public command maps to `plamen_driver.py --startup-intent START_NEW_RUN`;
   do not launch a second driver process.

On completion, report `AUDIT_REPORT.md`; on interruption, preserve all
artifacts and provide the ordinary resume command above.

## L1 config

Detect `go` versus `rust` from source files/manifests and ask if ambiguous.
Collect the explicit tier (`t0`..`t3`) and optional subsystem/fork scope. The
JSON keys are `project_root`, `scratchpad`, `mode`, `pipeline: "l1"`,
`language`, `cli_backend: "codex"`, `tier`, `subsystem_scope`, `fork_mode`,
`docs_path`, and `proven_only`.
