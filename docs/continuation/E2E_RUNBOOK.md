# Pinned DODO release-candidate E2E runbook

Status: **INCOMPLETE — the Codex baseline attempt was intentionally paused
after Recon; Claude has not launched**

These audits validate pipeline execution without comparing against private or
ground-truth findings. The V3 product retains `plamen_driver.py` and its V2
phase/checkpoint protocol as internal compatibility names; that Python driver
is the sole phase sequencer. Never
manually run or replace recon, breadth, depth, verification, or report phases.

## Frozen target identity

- Repository: `https://github.com/sherlock-audit/2025-05-dodo-cross-chain-dex.git`
- Commit: `d4834a468f7dad56b007b4450397289d4f767757`
- Audit project below each clone: `omni-chain-contracts`
- Documentation input below each clone: `README.md`
- Expected language: `evm`

The target deliberately contains both `yarn.lock` and `package-lock.json`
without machine-authoritative package-manager selection. Do not edit either
lock or add `packageManager`. Preserve typed `AMBIGUOUS_JS_LOCKS` debt; an E2E
report is not proof-grade compiler or PoC closure while that debt remains.

## Release and destination preconditions

1. Freeze and push the final Plamen source commit. The paused Codex attempt ran
   from `d42b851e706d30ab4f921f1384fc9fea290a0114`, which is not a final release
   candidate because its clean Windows install-smoke exposed an omitted Python
   MCP source closure.
2. Clone that exact final commit into a new source directory, run the governed
   Windows install once, and require `plamen doctor` to authenticate the exact
   source/package receipt.
3. Do not reuse any earlier target clone, `.scratchpad`, failed staged output,
   or E2E destination.
4. Run Codex first. Run Claude only after the Codex process is terminal; never
   run these two release-candidate audits concurrently.

On the retained Windows host, choose one explicit absolute `<E2E_WORK_ROOT>`
outside the source, installed package, and target repositories. Use these
distinct children, replacing `<plamen-short-sha>` with the final pushed Plamen
commit prefix:

```text
<E2E_WORK_ROOT>\<plamen-short-sha>\dodo-codex
<E2E_WORK_ROOT>\<plamen-short-sha>\dodo-claude
<E2E_WORK_ROOT>\<plamen-short-sha>\logs
```

Clone and pin each destination independently:

```powershell
$e2eWorkRoot = "<explicit-absolute-E2E-work-root>"
$releaseRoot = Join-Path $e2eWorkRoot "<plamen-short-sha>"
$targetUrl = "https://github.com/sherlock-audit/2025-05-dodo-cross-chain-dex.git"
$targetCommit = "d4834a468f7dad56b007b4450397289d4f767757"
New-Item -ItemType Directory -Force -Path $releaseRoot, "$releaseRoot\logs"

git clone $targetUrl "$releaseRoot\dodo-codex"
git -C "$releaseRoot\dodo-codex" checkout --detach $targetCommit
git -C "$releaseRoot\dodo-codex" rev-parse HEAD

git clone $targetUrl "$releaseRoot\dodo-claude"
git -C "$releaseRoot\dodo-claude" checkout --detach $targetCommit
git -C "$releaseRoot\dodo-claude" rev-parse HEAD
```

Both printed target identities must equal the full pinned commit.

## Provider-free preflight

For each clone, set `$clone`, then require both checks to pass before creating
audit state:

```powershell
$project = "$clone\omni-chain-contracts"
$docs = "$clone\README.md"
plamen --detect-language $project
plamen plan thorough $project --codex --docs $docs --json
```

Language detection must return `evm`; the JSON plan must report
`launchable: true`. For the Claude destination, replace `--codex` with
`--claude` in the plan command.

## Exact config

Create only `<project>\.scratchpad\config.json` initially. There must be no
other scratchpad artifact before `start-config`.

Codex config:

```json
{
  "project_root": "<absolute-clone>\\omni-chain-contracts",
  "scratchpad": "<absolute-clone>\\omni-chain-contracts\\.scratchpad",
  "mode": "thorough",
  "pipeline": "sc",
  "language": "evm",
  "cli_backend": "codex",
  "claude_exec_mode": "headless",
  "allow_model_fallback": false,
  "docs_path": "<absolute-clone>\\README.md",
  "scope_file": "",
  "scope_notes": "",
  "proven_only": false
}
```

Claude config is identical except:

```json
"cli_backend": "claude"
```

Do not enable model fallback merely to make a run advance. Requested and
observed route/model/fallback state must remain evidence-bound.

## Start and resume

Resolve the installed public launcher and start one new audit in the
background. Redirect logs outside the target and scratchpad:

```powershell
$front = (Get-Command plamen).Source
$config = "$project\.scratchpad\config.json"
$stdout = "$releaseRoot\logs\dodo-codex.stdout.log"
$stderr = "$releaseRoot\logs\dodo-codex.stderr.log"
$quotedConfig = '"' + $config + '"'
$run = Start-Process -FilePath $front `
  -ArgumentList @("start-config", $quotedConfig) `
  -WorkingDirectory $project `
  -WindowStyle Hidden -PassThru `
  -RedirectStandardOutput $stdout `
  -RedirectStandardError $stderr
$run.Id
```

Use `dodo-claude.*.log` for the later Claude run. `start-config` is for a new
destination only. After a genuine interruption, use only:

```powershell
plamen resume "$project\.scratchpad\config.json"
```

Never convert a failed destination into a fresh run by editing its checkpoint
or staged outputs. A new attempt gets a new clean destination.

## Monitoring and acceptance

Observe the live process handle, logs, driver log, and checkpoint:

```powershell
Get-Process -Id $run.Id
Get-Content $stdout -Tail 80
Get-Content $stderr -Tail 80
Get-Content "$project\.scratchpad\_plamen.log" -Tail 120
Get-Content "$project\.scratchpad\_v2_checkpoint.json"
```

A lock or checkpoint alone is not proof that a process is live. Observation
timeouts are not terminal outcomes; poll the same process handle and inspect
the driver-owned state before deciding that it stopped.

Each backend gate requires all of the following on the same frozen Plamen
source/package identity and pinned target identity:

- the process reaches a driver-owned terminal success with exit status zero;
- the checkpoint records all applicable phase commits through Report;
- `AUDIT_REPORT.md` exists at the audit-project root and passes report gates;
- typed dependency/build debt, route/model facts, degradation, retries, and
  unresolved obligations remain visible rather than being silently cleared;
- a clean interruption/resume exercise preserves generation and denominator
  identity without reusing rejected staged output; and
- logs, checkpoint, report, package receipt, Plamen commit, and target commit
  are captured in a hash-bound evidence record.

After each terminal run, update `EVIDENCE_INDEX.json` and the affected
`REQUIREMENTS.jsonl` rows. A partial phase observation is useful evidence but
does not close either E2E gate.
