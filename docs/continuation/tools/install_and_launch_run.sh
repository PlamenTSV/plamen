#!/bin/sh
# Usage: RUN=run44 sh docs/continuation/tools/install_and_launch_run.sh
# Preconditions: staging at /Users/ptsanev/dodo-v3-validation-${RUN}/ (byte-identical copy of run41 project tree, no .scratchpad) and its config.json written.
: "${RUN:?set RUN=runNN}"
# Gated: run ONLY after the 3.12 targeted gate is green. Idempotent-safe: refuses if ${RUN} already has a driver.
set -eu
SRC=/Users/ptsanev/plamen-v3
PY=/Users/ptsanev/.local/share/plamen/runtime/py312/bin/python
PROV=/Users/ptsanev/.plamen/.plamen-posix-compat-v2-provenance.json
CFG=/Users/ptsanev/dodo-v3-validation-${RUN}/omni-chain-contracts/.scratchpad/config.json
LOG=/Users/ptsanev/dodo-v3-validation-${RUN}/driver.log

# Anchored on the real driver command line: a monitor shell that merely MENTIONS the pattern cannot match.
ps -axo command | grep -qE "^\S*[Pp]ython\S* -I -B /Users/ptsanev/.plamen/plamen.py (start-config|resume)" && { echo "REFUSE: a driver is already running"; exit 2; }
test -f "$CFG" || { echo "REFUSE: ${RUN} config missing"; exit 2; }
BEFORE=$(python3 -c "import json;print(json.load(open('$PROV'))['generation_sha256'][:12])")
echo "generation before: $BEFORE"

cd "$SRC"
/opt/homebrew/opt/python@3.12/bin/python3.12 scripts/posix_v2_compat_install.py --posix-compat-v2 --install --source "$SRC" --python "$PY"

AFTER=$(python3 -c "import json;print(json.load(open('$PROV'))['generation_sha256'][:12])")
echo "generation after:  $AFTER"
[ "$AFTER" != "$BEFORE" ] || { echo "REFUSE: generation unchanged after install"; exit 3; }
# the installed tree must carry today's fixes
grep -qF "_PARENT_NAME_CACHE_LIMIT" /Users/ptsanev/.plamen/scripts/rooted_path_io.py || { echo "REFUSE: installed tree lacks the rooted_path_io cache fix"; exit 3; }
grep -qF "A thematic break" /Users/ptsanev/.plamen/scripts/inventory_reconciliation.py || { echo "REFUSE: installed reconciler lacks the thematic-break fix"; exit 3; }
grep -qF '(?P<value>[ \t]*.*?)' /Users/ptsanev/.plamen/scripts/inventory_reconciliation.py || { echo "REFUSE: installed reconciler lacks the source-id regex fix"; exit 3; }
# `_effective_fetch_prompt` was a misdiagnosis and was DELETED (2026-09-19 §2 row 5); its presence means a stale tree.
grep -qF '_effective_fetch_prompt' /Users/ptsanev/.plamen/scripts/claude_phase_tool_policy.py && { echo "REFUSE: installed tool policy still carries the deleted _effective_fetch_prompt"; exit 3; }
# run43 blocker: the final ONE_TO_ONE_RETENTION path must grant the material-token check (two grant sites, chunk + final).
[ "$(grep -cF 'allow_run_alignment=True' /Users/ptsanev/.plamen/scripts/inventory_reconciliation.py)" = "2" ] || { echo "REFUSE: installed reconciler lacks the final-path preservation grant (run43 fix)"; exit 3; }
grep -qF 'move_to_end(key_path)' /Users/ptsanev/.plamen/scripts/rooted_path_io.py || { echo "REFUSE: installed rooted_path_io lacks the LRU correction"; exit 3; }
# run44 blocker: Claude CLI >= 2.1.278 ships the builtin `agents-md` plugin; the per-worker settings must DISABLE it explicitly.
grep -qF 'CLAUDE_SETTINGS_ENABLED_PLUGINS' /Users/ptsanev/.plamen/scripts/pty_exec.py || { echo "REFUSE: installed pty_exec lacks the builtin-plugin disable (run44 fix)"; exit 3; }
grep -qF 'settings_enabled_plugins_grant_nothing' /Users/ptsanev/.plamen/scripts/claude_phase_tool_policy.py || { echo "REFUSE: installed tool policy lacks the plugin-grant property check (run44 fix)"; exit 3; }
grep -qF '"enabledPlugins":{"agents-md@builtin":false}' /Users/ptsanev/.plamen/scripts/pty_exec.py || { echo "REFUSE: installed isolation payload does not disable agents-md@builtin"; exit 3; }
# §3.1/§3.2 (R-EXT): no blanket per-denial issue; one prior denial tolerated.
grep -qF 'dependency web request was denied' /Users/ptsanev/.plamen/scripts/claude_phase_tool_policy.py && { echo "REFUSE: installed tool policy still emits blanket denial issues (§3.1)"; exit 3; }
grep -qF 'prior_denials >= 2' /Users/ptsanev/.plamen/scripts/claude_phase_tool_policy.py || { echo "REFUSE: installed tool policy lacks the one-denial tolerance (§3.2)"; exit 3; }
grep -qF 'session_fetched_urls' /Users/ptsanev/.plamen/scripts/claude_phase_tool_policy.py || { echo "REFUSE: installed tool policy lacks the session-wide claim property (run45 R-EXT fix)"; exit 3; }
grep -qF 'The inventory CHUNKS are deliberately NOT promoted' /Users/ptsanev/.plamen/scripts/plamen_types.py || { echo "REFUSE: installed types still route inventory chunks to Opus (run45 refusal fix)"; exit 3; }
grep -qF '_stream_stalled(now, stdout_reader, stderr_reader)' /Users/ptsanev/.plamen/scripts/posix_v2_compat_runtime.py || { echo "REFUSE: installed runtime lacks the stream-inactivity watchdog (run45 chunk_c hang)"; exit 3; }
grep -qF '"model_refusal_no_fallback",' /Users/ptsanev/.plamen/scripts/claude_stream_json_evidence.py || { echo "REFUSE: installed stream grammar does not admit the typed provider refusal (§3.5)"; exit 3; }
grep -qF '_PROVIDER_REFUSAL_CODES' /Users/ptsanev/.plamen/scripts/posix_v2_compat_runtime.py || { echo "REFUSE: installed runtime does not map PROVIDER_REFUSAL to PROVIDER_REFUSED"; exit 3; }
# run45 aggregate halt: unparseable source facets are visible debt, never a halt.
grep -qF '_irreparable_source_facet_ambiguity' /Users/ptsanev/.plamen/scripts/plamen_validators.py || { echo "REFUSE: installed validators still halt on irreparable UNPARSEABLE debt"; exit 3; }
grep -qF 'if not str(axis).startswith("UNPARSEABLE_")' /Users/ptsanev/.plamen/scripts/inventory_reconciliation.py || { echo "REFUSE: installed reemit loader still counts UNPARSEABLE as loss"; exit 3; }
grep -qF '"REEMIT_UNPARSEABLE_SOURCE_DEBT"' /Users/ptsanev/.plamen/scripts/inventory_reemit_authority.py || { echo "REFUSE: installed reemit authority replay rejects unparseable-debt deliveries"; exit 3; }
grep -qF '_table_speaks_dispositions' /Users/ptsanev/.plamen/scripts/candidate_negative_authority.py || { echo "REFUSE: installed candidate-negative harvester still mints phantom candidates from registers (run46 B3)"; exit 3; }
grep -qF 'semantic_invariant_pass1_snapshot.md` — the driver' /Users/ptsanev/.plamen/prompts/shared/v2/phase4a5-invariants-p2.md || { echo "REFUSE: installed Pass-2 invariants template still reads the live output (run46)"; exit 3; }
grep -qF 'is a mandated read in' /Users/ptsanev/.plamen/scripts/phase_io_contracts.py || { echo "REFUSE: installed Pass-1 invariants contract lacks function_list.md (run46)"; exit 3; }
# run46 depth: own-output reads and quoted skill paths must not be denied by the worker prompt checker.
grep -qF '_without_quoted_tokens' /Users/ptsanev/.plamen/scripts/claude_worker_prompt_consistency.py || { echo "REFUSE: installed prompt checker still denies quoted skill paths as coordinator instructions (run46 depth)"; exit 3; }
[ "$(grep -cF 'and not output_authority.contains(' /Users/ptsanev/.plamen/scripts/claude_worker_prompt_consistency.py)" -ge 2 ] || { echo "REFUSE: installed prompt checker still denies own-output reads (run46 depth)"; exit 3; }
grep -qF '_block_attests_zero_candidates' /Users/ptsanev/.plamen/scripts/candidate_negative_authority.py || { echo "REFUSE: installed harvester still mints phantom entities from zero-candidate attestation sections (run47 B6)"; exit 3; }
grep -qF 'seal_application_payload' /Users/ptsanev/.plamen/scripts/semantic_invariant_authority.py || { echo "REFUSE: installed semantic-invariant authority still demands model-computed digests (run47 invariants)"; exit 3; }
# run47 death (2026-09-20 11:33): a resume must recompute the launch-time input-preparation posture or every snapshot-bound receipt rejects the run.
grep -qF '_restore_snapshot_input_preparation(checkpoint, config)' /Users/ptsanev/.plamen/scripts/plamen_driver.py || { echo "REFUSE: installed driver still recomputes a different snapshot digest on resume (run47 resume fix 1)"; exit 3; }
# run47 pause (10:44): the CLI's framed rate_limit_event carries an exact resetsAt; bounded windows are waited out unattended, never paused for an operator.
grep -qF 'claude_event_framed' /Users/ptsanev/.plamen/scripts/plamen_mechanical.py || { echo "REFUSE: installed estimator cannot parse the Claude Code rate_limit_event reset (run47)"; exit 3; }
grep -qF '_rate_limit_wait_plan(' /Users/ptsanev/.plamen/scripts/plamen_driver.py || { echo "REFUSE: installed driver still pauses on bounded authoritative reset windows (run47)"; exit 3; }
# run47 death (fix 2): resume must classify the driver's own in-run rewrites instead of rewinding every completed phase.
grep -qF 'detect_resume_semantic_drift' /Users/ptsanev/.plamen/scripts/plamen_driver.py || { echo "REFUSE: installed driver still gates resume on raw input drift (run47 resume fix 2)"; exit 3; }
grep -qF 'INTRA_RUN_PRODUCER_RECEIPT_CASCADE' /Users/ptsanev/.plamen/scripts/artifact_ledger.py || { echo "REFUSE: installed ledger still treats a sibling producer-receipt cascade as external drift"; exit 3; }
grep -qF 'def detect_committed_output_tamper' /Users/ptsanev/.plamen/scripts/artifact_ledger.py || { echo "REFUSE: installed ledger lacks the committed-output seal scan (the resume tamper authority)"; exit 3; }
grep -qF 'RUN_BINDING_PROJECTION_SCHEMA' /Users/ptsanev/.plamen/scripts/artifact_ledger.py || { echo "REFUSE: installed ledger still content-hashes _v2_checkpoint.json as an exact input"; exit 3; }
grep -qF 'EXTERNAL_DRIFT_WITH_UNTYPED_DESCENDANT' /Users/ptsanev/.plamen/scripts/plamen_driver.py || { echo "REFUSE: installed driver lacks the scoped untyped-descendant repair (run47 resume fix 2)"; exit 3; }
grep -qF 'INPUT_DRIFT_WITH_UNTYPED_DESCENDANT' /Users/ptsanev/.plamen/scripts/plamen_driver.py && { echo "REFUSE: installed driver still carries the unscoped suffix-rewind fallback that killed run47"; exit 3; }
# 2026-09-20 downstream discovery (docs/continuation/DISCOVERY_SYNTHESIS_2026-09-20.json): depth- and dedup-class fail-closed recognizers.
grep -qF '_TABLE_DISPOSITION_HEADERS' /Users/ptsanev/.plamen/scripts/candidate_negative_authority.py || { echo "REFUSE: installed harvester still reads a Severity tier cell as a disposition (action 12)"; exit 3; }
grep -qF '_DECORATED_TABLE_ID_RE' /Users/ptsanev/.plamen/scripts/candidate_negative_authority.py || { echo "REFUSE: installed harvester still denies bracketed identity cells (action 12)"; exit 3; }
grep -qF '_NON_BLOCKING_CANDIDATE_NEGATIVE_DEBT' /Users/ptsanev/.plamen/scripts/candidate_negative_authority.py || { echo "REFUSE: installed harvester still denies an artifact for committed-invariant debt (action 13)"; exit 3; }
grep -qF 'STRICT_OBLIGATION_RECEIPT' /Users/ptsanev/.plamen/scripts/candidate_negative_authority.py || { echo "REFUSE: installed harvester lacks the obligation-receipt harvest (action 11)"; exit 3; }
grep -qF '_receipt_claim_text' /Users/ptsanev/.plamen/scripts/security_obligation_authority.py || { echo "REFUSE: installed obligation authority still rejects receipt-like MENTIONS (action 15)"; exit 3; }
# run48 depth (20:57): every core depth worker SUCCEEDED and staged its artifact, and the staged obligation validator rejected it -- nothing published.
grep -qF '"<!--" not in line' /Users/ptsanev/.plamen/scripts/security_obligation_authority.py || { echo "REFUSE: installed obligation authority still rejects a prose MENTION of the evidence marker (run48 depth)"; exit 3; }
grep -qF '_depth_graph_projection_is_populated' /Users/ptsanev/.plamen/scripts/plamen_driver.py || { echo "REFUSE: installed graph gate still demands exactly-once markers (action 16)"; exit 3; }
grep -qF '_family_regex_source' /Users/ptsanev/.plamen/scripts/claude_worker_prompt_consistency.py || { echo "REFUSE: installed prompt checker still denies family read tokens (action 8)"; exit 3; }
grep -qF '_list_span_members' /Users/ptsanev/.plamen/scripts/claude_worker_prompt_consistency.py || { echo "REFUSE: installed prompt checker still reads a backticked artifact list as one token (action 1)"; exit 3; }
grep -qF '_model_and_driver_expected_artifacts' /Users/ptsanev/.plamen/scripts/plamen_prompt.py || { echo "REFUSE: installed prompt renderer still names driver-written artifacts in a write directive (action 1)"; exit 3; }
grep -qF 'every exact verifier unit in this tier was refused' /Users/ptsanev/.plamen/scripts/plamen_driver.py || { echo "REFUSE: installed driver still halts on a single verifier refusal (action 6)"; exit 3; }
grep -qF '_candidate_negative_delivered_ids' /Users/ptsanev/.plamen/scripts/plamen_validators.py || { echo "REFUSE: installed promotion receipt still flags ledger-delivered breadth candidates (action 2)"; exit 3; }
grep -qF '_unique_relative_suffix' /Users/ptsanev/.plamen/scripts/claude_worker_prompt_consistency.py || { echo "REFUSE: installed prompt checker still denies a registered artifact named by its relative path"; exit 3; }
grep -qF '_consolidation_subject_ids' /Users/ptsanev/.plamen/scripts/report_disposition_authority.py || { echo "REFUSE: installed disposition authority still treats a consolidation survivor as a subject (action 3)"; exit 3; }
grep -qF '_is_pattern_governed' /Users/ptsanev/.plamen/scripts/claude_worker_prompt_consistency.py || { echo "REFUSE: installed prompt checker still treats a search PATTERN as a search root (action 10)"; exit 3; }
grep -qF '_verification_runtime_debt_coverage(\n            scratchpad, missing\n        )' /Users/ptsanev/.plamen/scripts/plamen_validators.py || grep -qF 'covered, debt_issues = _verification_runtime_debt_coverage' /Users/ptsanev/.plamen/scripts/plamen_validators.py || { echo "REFUSE: installed queue parity still counts retained runtime debt as missing (action 18)"; exit 3; }
grep -qF 'fall back to `report_index.md`' /Users/ptsanev/.plamen/prompts/shared/v2/phase6b-tier-writers.md && { echo "REFUSE: installed tier-writer template still carries the contract-forbidden report_index fallback (action 4)"; exit 3; }
grep -qF 'auxiliary usage provenance changed' /Users/ptsanev/.plamen/scripts/posix_v2_compat_claude.py || { echo "REFUSE: installed compat gate is not today's"; exit 3; }
grep -qF 'row.get("webSearchRequests") != 0' /Users/ptsanev/.plamen/scripts/posix_v2_compat_claude.py && { echo "REFUSE: installed compat gate still requires zero auxiliary searches"; exit 3; }

nohup /Users/ptsanev/.local/bin/plamen start-config "$CFG" --posix-compat-v2 > "$LOG" 2>&1 &
sleep 5
# The managed runtime's sys.executable resolves to the Homebrew Cellar binary, so anchor on the driver argv, not the venv path.
PID=$(ps -axo pid,command | grep -E "^ *[0-9]+ \S*[Pp]ython\S* -I -B /Users/ptsanev/.plamen/plamen.py start-config.*${RUN}" | awk "{print \$1}" | head -1)
echo "${RUN} driver pid: ${PID:-NOT FOUND}"; echo "driver log: $LOG"
