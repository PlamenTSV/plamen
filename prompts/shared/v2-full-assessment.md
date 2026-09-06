# V2 Full-Pipeline Assessment — Post-Optimization

> **Purpose**: Comprehensive forensic verification of the Plamen V2 driver after all optimization phases (Opus 4.7 alignment, chain pre-filter, SC prebake, critical fixes).
> **Usage**: After a V2 audit completes or crashes, paste this into a new Claude Code conversation at the project root.
> **Driver version**: 2804 lines, 42 phases, 17 critical fixes applied.

You are performing an adversarial post-audit assessment. Find every failure, gap, skipped step, silent error, quality issue, and inconsistency. Do not praise what worked — report evidence.

---

## STEP 0: ARTIFACT DISCOVERY

```bash
S=".scratchpad"
echo "=== CONFIG ==="
cat "$S/config.json"

echo "=== CHECKPOINT (full) ==="
cat "$S/pipeline_checkpoint.md"

echo "=== VIOLATIONS ==="
cat "$S/violations.md" 2>/dev/null || echo "NONE"

echo "=== INSTANTIATION ==="
cat "$S/instantiation.json" 2>/dev/null || echo "MISSING"

echo "=== FILE INVENTORY ==="
ls -la "$S/" | head -120

echo "=== REPORT EXISTS? ==="
ls -la AUDIT_REPORT*.md 2>/dev/null
```

Record: MODE, LANGUAGE, PIPELINE from config.json.

---

## SECTION A — DRIVER INFRASTRUCTURE

### A1. Checkpoint completeness and continuity

```bash
echo "Phase count in checkpoint:"
grep -cE "^\- \w+: (PASS|FAIL)" "$S/pipeline_checkpoint.md"

echo "Resumed phases (from prior sessions):"
grep -c "(resumed)" "$S/pipeline_checkpoint.md"

echo "Any interrupted phase:"
grep "Interrupted During" "$S/pipeline_checkpoint.md"

echo "Mode/Pipeline/Language header:"
head -5 "$S/pipeline_checkpoint.md"
```

**PASS if**: Checkpoint has header (Mode/Pipeline/Language/Last updated), shows resumed phases from prior sessions (if any), and lists every expected phase for the mode. No "Interrupted During" without a subsequent completion.

**FAIL if**: Only final session phases visible (checkpoint overwrite regression). Missing header fields.

### A2. Rate limit handling

```bash
grep -c "RATE_LIMITED" "$S/pipeline_checkpoint.md"
grep "RATE LIMIT\|exit.*2\|Pipeline PAUSED" "$S/violations.md" 2>/dev/null
```

**PASS if**: Every rate-limit event has a checkpoint entry and the pipeline resumed correctly.

### A3. Encoding safety

```bash
python -c "
from pathlib import Path
bad = []
for p in Path('$S').glob('*.md'):
    try: p.read_text(encoding='utf-8')
    except UnicodeDecodeError as e: bad.append((p.name, str(e)[:60]))
for p in Path('$S').glob('*.json'):
    try: p.read_text(encoding='utf-8')
    except UnicodeDecodeError as e: bad.append((p.name, str(e)[:60]))
print('UTF-8 errors:', bad if bad else 'NONE')
"
```

### A4. Config validity

```bash
python -c "
import json
cfg = json.load(open('$S/config.json'))
for k in ['project_root','scratchpad','mode','pipeline','language']:
    print(f'  {k}: {cfg.get(k, \"MISSING\")}')" 2>/dev/null
```

---

## SECTION B — SC PREBAKE (NEW)

```bash
echo "=== Prebake status ==="
cat "$S/slither/primitive_status.md" 2>/dev/null || echo "NO PREBAKE"

echo "=== Prebake files ==="
ls -la "$S/slither/"*.md 2>/dev/null

echo "=== Prebake file sizes ==="
for f in call_graph.md state_write_map.md function_summary.md inheritance_tree.md access_control_map.md detector_findings.md; do
    FILE="$S/slither/$f"
    if [ -f "$FILE" ]; then
        echo "  OK: $f ($(wc -l < "$FILE") lines, $(wc -c < "$FILE") bytes)"
    else
        echo "  MISSING: $f"
    fi
done

echo "=== SLITHER_PREBAKE_COMPLETE flag ==="
grep "SLITHER_PREBAKE_COMPLETE" "$S/slither/primitive_status.md" 2>/dev/null

echo "=== project_facts.json exists? ==="
ls -la "$S/slither/project_facts.json" 2>/dev/null || echo "MISSING"

echo "=== Prebake phase in checkpoint ==="
grep "sc_bake\|sc_prebake" "$S/pipeline_checkpoint.md"
```

**PASS if** (EVM only):
- `primitive_status.md` exists with `SLITHER_AVAILABLE: true` and `SLITHER_PREBAKE_COMPLETE: true`
- All 6 flat files exist with >50 bytes each
- `project_facts.json` exists (gate marker)
- Both `sc_bake` and `sc_prebake` appear in checkpoint as PASS
- `call_graph.md` contains actual function-call table rows (not just headers)
- `detector_findings.md` has High/Medium findings (not empty)

**FAIL if**: EVM audit but no prebake artifacts (Slither/forge not available — acceptable degradation) vs prebake attempted but produced empty files (bug).

**N/A if**: Non-EVM language.

### B2. Prebake consumed by agents

```bash
echo "=== Breadth prompt references slither ==="
grep -ci "slither\|Structural Orientation\|call_graph\|function_summary" "$S/_prompt_breadth.md" 2>/dev/null

echo "=== Depth prompt references slither ==="
grep -ci "slither\|Prebake\|call_graph\|state_write_map" "$S/_prompt_depth.md" 2>/dev/null
```

**PASS if**: Breadth prompt has structural orientation section (>0 hits). Depth prompt has Slither directive (>0 hits).

**FAIL if**: Prebake completed but prompts don't reference the files (agents won't read them).

---

## SECTION C — RECON

```bash
for f in recon_summary.md design_context.md attack_surface.md state_variables.md function_list.md contract_inventory.md template_recommendations.md build_status.md; do
    FILE="$S/$f"
    [ -f "$FILE" ] && echo "OK: $f ($(wc -c < "$FILE") bytes)" || echo "MISSING: $f"
done

echo "=== Operational Implications ==="
grep -c "## Operational Implications" "$S/design_context.md" 2>/dev/null

echo "=== Required templates in manifest ==="
grep -cE "\*\*YES\*\*" "$S/template_recommendations.md" 2>/dev/null

echo "=== Niche agents required ==="
sed -n '/Niche Agents/,/^##/p' "$S/template_recommendations.md" 2>/dev/null | grep -cE "\*\*YES\*\*"

echo "=== Build status ==="
grep -iE "MEDUSA|compile|forge|slither" "$S/build_status.md" 2>/dev/null
```

**FAIL if**: Any core artifact missing. No Operational Implications section. Zero Required templates.

---

## SECTION D — INSTANTIATION (Fix 1 + Fix 2)

```bash
python -c "
import json
d = json.load(open('$S/instantiation.json'))
print('mode:', d.get('mode'))
print('breadth_count:', d.get('breadth_count'))
print('depth_agents:', d.get('depth_agents'))
print('niche_agents:', d.get('niche_agents'))
print('skill_files count:', len(d.get('skill_files', [])))
for s in d.get('skill_files', []):
    print(' ', s)
print('total_agent_estimate:', d.get('total_agent_estimate'))
" 2>/dev/null

echo "=== Cross-reference: Required in manifest vs instantiation ==="
echo "Required templates:"
grep -oE "^\|\s+[A-Z_]+\s+\|[^|]+\|\s*\*?\*?YES" "$S/template_recommendations.md" 2>/dev/null | wc -l
echo "Required niche:"
sed -n '/Niche Agents/,/^##/p' "$S/template_recommendations.md" 2>/dev/null | grep -cE "\*\*YES\*\*"

echo "=== Skill files exist on disk? ==="
python -c "
import json, os
d = json.load(open('$S/instantiation.json'))
missing = [s for s in d.get('skill_files', []) if not os.path.exists(s)]
print('Missing:', missing if missing else 'NONE')
" 2>/dev/null
```

**PASS if**: `skill_files` count > 0 for Core/Thorough. `niche_agents` count matches manifest Required count. All skill file paths exist on disk.

**FAIL if**: `skill_files: []` (Fix 1 regressed). `niche_agents: []` when manifest has Required (Fix 2 regressed).

---

## SECTION E — BREADTH

```bash
echo "=== Breadth files ==="
ls "$S"/analysis_*.md 2>/dev/null | grep -vE "rescan|percontract"

echo "=== Count ==="
ls "$S"/analysis_*.md 2>/dev/null | grep -vE "rescan|percontract" | wc -l

echo "=== Per-file stats ==="
for f in $(ls "$S"/analysis_*.md 2>/dev/null | grep -vE "rescan|percontract"); do
    findings=$(grep -cE "^##+ Finding" "$f")
    size=$(wc -c < "$f")
    echo "  $(basename $f): $size bytes, $findings findings"
done

echo "=== Opus spawn mandate check ==="
grep -c "MUST spawn\|Opus 4.8 MANDATE\|spawn.*all.*anyway" "$S/_prompt_breadth.md" 2>/dev/null

echo "=== Expected vs actual ==="
python -c "
import json
d = json.load(open('$S/instantiation.json'))
print('Expected:', d.get('breadth_count'))
" 2>/dev/null
```

**FAIL if**: Actual count < expected breadth_count. Any agent file < 200 bytes (stub). FLASH_LOAN agent missing (NEVER MERGE rule). Zero spawn mandate keywords in prompt (Opus 4.8 mandate not applied).

---

## SECTION F — DEPTH (NEVER-CUT + Evidence Tags)

```bash
echo "=== Depth files ==="
for agent in depth_token_flow depth_state_trace depth_edge_case depth_external; do
    f="$S/${agent}_findings.md"
    [ -f "$f" ] && echo "OK: ${agent} ($(wc -c < "$f") bytes, $(grep -cE '^##+ Finding|^### Target' "$f") findings)" || echo "MISSING: ${agent} (NEVER-CUT VIOLATION)"
done

echo "=== Evidence tags ==="
for tag in BOUNDARY VARIATION TRACE CROSS-DOMAIN-DEP; do
    count=$(grep -rhoE "\[$tag[^]]*\]" "$S"/depth_*_findings.md 2>/dev/null | wc -l)
    echo "  [$tag]: $count"
done

echo "=== Mandatory tag enforcement ==="
grep -c "MANDATORY.*evidence tag\|INCOMPLETE.*flagged" "$S/_prompt_depth.md" 2>/dev/null

echo "=== Chain Summary sections ==="
for f in "$S"/depth_*_findings.md; do
    [ -f "$f" ] && echo "  $(basename $f): Chain Summary = $(grep -c 'Chain Summary' "$f")"
done

echo "=== Scanners ==="
for s in blind_spot_a blind_spot_b blind_spot_c scanner_a scanner_b scanner_c validation_sweep scanner_validation; do
    f="$S/${s}_findings.md"
    [ -f "$f" ] && echo "  OK: $s ($(wc -c < "$f") bytes)"
done

echo "=== Scanner C CHECK 5 ==="
grep -l "CHECK 5\|untrusted-call-target\|guard.*parameter" "$S"/*scanner*c*findings.md "$S"/blind_spot_c*.md 2>/dev/null

echo "=== Niche agent outputs ==="
ls "$S"/niche_*_findings.md 2>/dev/null

echo "=== Design stress (Thorough, UNCONDITIONAL) ==="
ls -la "$S/design_stress_findings.md" 2>/dev/null || echo "MISSING"
```

**FAIL if**: Any of 4 NEVER-CUT depth files missing. Zero evidence tags (was 0 in baseline, should be >0 now). No MANDATORY enforcement in depth prompt. Scanner C missing CHECK 5. Thorough mode but no design_stress_findings.md.

---

## SECTION G — DEPTH ITER2 (Fix 3: Gate Glob + Fix 5: DA Routing)

```bash
echo "=== depth_iter2 in checkpoint ==="
grep "depth_iter2" "$S/pipeline_checkpoint.md"

echo "=== depth_iter2 files on disk ==="
ls -la "$S"/depth_iter2*findings*.md 2>/dev/null

echo "=== depth_iter2 violations ==="
grep "depth_iter2" "$S/violations.md" 2>/dev/null

echo "=== DA framing in iter2 prompt ==="
grep -ciE "devil|adversarial|what.*missed|DA.*role|contrastive" "$S/_prompt_depth_iter2.md" 2>/dev/null || echo "NO PROMPT FILE"

echo "=== rescore and iter3 cascade ==="
grep "rescore\|depth_iter3" "$S/pipeline_checkpoint.md"
```

**PASS if**: depth_iter2 either ran successfully (PASS in checkpoint + files on disk) OR was correctly skipped (no UNCERTAIN Medium+ findings). DA prompt has >0 adversarial keywords. If iter2 succeeded, rescore ran after it.

**FAIL if**: depth_iter2 FAIL due to gate glob mismatch (regression — should be fixed). DA framing 0 keywords (routing still goes to generic depth driver instead of phase4b-da-iter2.md).

---

## SECTION H — CHAIN PRE-FILTER (NEW)

```bash
echo "=== chain_prefilter in checkpoint ==="
grep "chain_prefilter" "$S/pipeline_checkpoint.md"

echo "=== chain_candidate_pairs.md ==="
if [ -f "$S/chain_candidate_pairs.md" ]; then
    echo "EXISTS ($(wc -l < "$S/chain_candidate_pairs.md") lines)"
    head -10 "$S/chain_candidate_pairs.md"
    echo "---"
    echo "STATE pairs:"
    grep -c "^\| [0-9]" "$S/chain_candidate_pairs.md" 2>/dev/null
else
    echo "MISSING"
fi

echo "=== Composition coverage ==="
if [ -f "$S/composition_coverage.md" ]; then
    echo "Total rows: $(grep -c '^|' "$S/composition_coverage.md")"
    echo "EXPLORED: $(grep -ciE 'explored|YES' "$S/composition_coverage.md")"
    echo "EXCLUDED: $(grep -ciE 'EXCLUDED' "$S/composition_coverage.md")"
    echo "NOT EXPLORED: $(grep -ciE 'NOT EXPLORED' "$S/composition_coverage.md" | grep -cv 'EXCLUDED')"
else
    echo "MISSING"
fi

echo "=== Chain hypotheses ==="
grep -c "^| CH-\|^## Chain Hypothesis" "$S/chain_hypotheses.md" 2>/dev/null

echo "=== Hypotheses count ==="
grep -c "^| H-" "$S/hypotheses.md" 2>/dev/null
```

**PASS if**: `chain_candidate_pairs.md` exists with STATE and TYPE pair tables. Composition coverage shows EXCLUDED for non-candidate pairs (not NOT EXPLORED). Coverage of candidate pairs is >80%.

**FAIL if**: Pre-filter produced 0 candidate pairs when findings > 10. Or pre-filter missing entirely (fallback to old algorithm OK but suboptimal).

---

## SECTION I — CONFIDENCE SCORING (Fix: uncertain cross-reference)

```bash
echo "=== Confidence file ==="
ls -la "$S/confidence_scores.md" 2>/dev/null

echo "=== Scoring axes ==="
grep -ciE "Evidence|Consensus|Analysis.Quality" "$S/confidence_scores.md" 2>/dev/null

echo "=== Classifications ==="
for level in CONFIDENT UNCERTAIN LOW_CONFIDENCE CONTESTED; do
    echo "  $level: $(grep -c "$level" "$S/confidence_scores.md" 2>/dev/null)"
done

echo "=== depth_iter2 triggered correctly? ==="
echo "UNCERTAIN findings:"
grep -c "UNCERTAIN" "$S/confidence_scores.md" 2>/dev/null
echo "depth_iter2 in checkpoint:"
grep "depth_iter2" "$S/pipeline_checkpoint.md"
```

**FAIL if**: UNCERTAIN Medium+ findings exist but depth_iter2 was skipped (cross-reference bug regressed).

---

## SECTION J — VERIFICATION

```bash
echo "=== Verify files ==="
ls "$S"/verify_*.md 2>/dev/null | wc -l

echo "=== Evidence tags ==="
for tag in POC-PASS POC-FAIL CODE-TRACE MEDUSA-PASS FUZZ-PASS; do
    count=$(grep -rhoE "\[$tag\]" "$S"/verify_*.md 2>/dev/null | wc -l)
    echo "  [$tag]: $count"
done

echo "=== Suggested fixes ==="
grep -c "### Suggested Fix" "$S"/verify_*.md 2>/dev/null | awk -F: '{s+=$2} END {print s+0}'

echo "=== Completeness ==="
grep "completeness" "$S/pipeline_checkpoint.md"

echo "=== Verification queue ==="
head -5 "$S/verification_queue.md" 2>/dev/null

echo "=== Active vs verified ==="
python -c "
import re
q = open('$S/verification_queue.md').read()
print('Queue:', re.search(r'Total: (\d+).*Remaining: (\d+)', q).groups() if re.search(r'Total: (\d+).*Remaining: (\d+)', q) else 'PARSE FAIL')
" 2>/dev/null
```

**FAIL if**: Active hypothesis count != verified count. Any Critical/High without Suggested Fix.

---

## SECTION K — SKEPTIC-JUDGE (Thorough)

```bash
echo "=== Skeptic files ==="
ls "$S"/skeptic_*.md 2>/dev/null | wc -l
echo "=== Judge files ==="
ls "$S"/judge_*.md 2>/dev/null | wc -l

echo "=== HIGH/CRIT hypothesis count ==="
python -c "
import re
h = open('$S/hypotheses.md').read()
hc = len(re.findall(r'^\|\s*H-\w+[^|]*\|[^|]*\|\s*(Critical|High)', h, re.M))
print('HIGH/CRIT:', hc)
" 2>/dev/null

echo "=== Coverage ==="
echo "Skeptic files: $(ls "$S"/skeptic_*.md 2>/dev/null | wc -l)"
```

**FAIL if**: Thorough mode but HIGH/CRIT count > skeptic file count.

---

## SECTION L — REPORT (Fix 3 staleness + Fix 4 gates + Fix 7 scrubber)

```bash
echo "=== Report file ==="
ls -la AUDIT_REPORT.md 2>/dev/null

echo "=== Sections per tier ==="
echo "  Critical: $(grep -c '^### \[C-' AUDIT_REPORT.md 2>/dev/null)"
echo "  High: $(grep -c '^### \[H-' AUDIT_REPORT.md 2>/dev/null)"
echo "  Medium: $(grep -c '^### \[M-' AUDIT_REPORT.md 2>/dev/null)"
echo "  Low: $(grep -c '^### \[L-' AUDIT_REPORT.md 2>/dev/null)"
echo "  Info: $(grep -c '^### \[I-' AUDIT_REPORT.md 2>/dev/null)"

echo "=== Summary table ==="
grep -A6 "| Severity" AUDIT_REPORT.md 2>/dev/null | head -8

echo "=== Total sections vs summary ==="
python -c "
import re
rpt = open('AUDIT_REPORT.md').read()
sections = len(re.findall(r'^### \[[CHMLI]-\d+\]', rpt, re.M))
sm = re.search(r'\| Critical \| (\d+) \|.*?\| High \| (\d+) \|.*?\| Medium \| (\d+) \|.*?\| Low \| (\d+) \|.*?\| Informational \| (\d+) \|', rpt, re.DOTALL)
summary = sum(int(g) for g in sm.groups()) if sm else -1
print(f'Sections: {sections}, Summary: {summary}, Match: {sections == summary}')
" 2>/dev/null

echo "=== Appendix A ==="
grep -c "## Appendix A" AUDIT_REPORT.md 2>/dev/null

echo "=== Internal ID leaks in body ==="
python -c "
import re
rpt = open('AUDIT_REPORT.md').read()
parts = re.split(r'(?=## Appendix A:)', rpt, maxsplit=1)
body = parts[0]
ids = re.findall(r'\[(?:CS|AC|TF|BLIND|EN|SE|VS|DEPTH|SLITHER|RS|PC|SP|DST|DE|DX|DS|DT)-\d+\]', body)
print(f'Internal IDs in body: {len(ids)}')
if ids: print(f'  Sample: {ids[:5]}')
" 2>/dev/null

echo "=== Claude metadata in body ==="
python -c "
import re
rpt = open('AUDIT_REPORT.md').read()
parts = re.split(r'(?=## Appendix A:)', rpt, maxsplit=1)
hits = re.findall(r'\b(Claude|Anthropic|Opus\s+\d|Sonnet\s+\d|Haiku\s+\d)\b', parts[0], re.I)
print(f'Claude metadata: {len(hits)}')
" 2>/dev/null

echo "=== report_quality.md ==="
cat "$S/report_quality.md" 2>/dev/null || echo "MISSING"

echo "=== report_coverage.md ==="
ls -la "$S/report_coverage.md" 2>/dev/null || echo "MISSING"

echo "=== Tier file mtimes vs report mtime ==="
python -c "
from pathlib import Path
rpt = Path('AUDIT_REPORT.md')
if not rpt.exists():
    print('NO REPORT')
else:
    rpt_mt = rpt.stat().st_mtime
    for name in ['report_critical_high.md','report_medium.md','report_low_info.md','report_index.md']:
        tf = Path('$S') / name
        if tf.exists():
            tf_mt = tf.stat().st_mtime
            stale = 'STALE' if tf_mt > rpt_mt else 'ok'
            print(f'  {name}: {stale} (tier={tf_mt:.0f}, report={rpt_mt:.0f}, diff={tf_mt-rpt_mt:.0f}s)')
" 2>/dev/null

echo "=== report_assemble behavior ==="
grep "report_assemble" "$S/pipeline_checkpoint.md"

echo "=== report_gates ==="
grep "report_gates" "$S/pipeline_checkpoint.md"
```

**CRITICAL FAIL if**: Section count != summary total (Fix 3 staleness regression — report_assemble skipped despite stale tiers). Any tier file mtime > report mtime AND report_assemble shows 0.0s duration (ghost-skip reoccurred).

**FAIL if**: Internal IDs in body > 0. Claude metadata > 0. Appendix A missing. report_quality.md missing. report_coverage.md missing.

---

## SECTION M — WASTE & EFFICIENCY

```bash
echo "=== Phases at max timeout ==="
python -c "
import re
cp = open('$S/pipeline_checkpoint.md').read()
for m in re.finditer(r'- (\w+): \w+ \(exit=\d+, (\d+\.\d+)s', cp):
    name, dur = m.group(1), float(m.group(2))
    if dur >= 1750:
        print(f'  TIMEOUT: {name} ({dur:.0f}s)')
"

echo "=== Retry waste ==="
grep "retries=" "$S/pipeline_checkpoint.md"

echo "=== Short-exit guards triggered ==="
grep "short-exit" "$S/violations.md" 2>/dev/null

echo "=== Ghost-phase checks ==="
grep "report_assemble" "$S/pipeline_checkpoint.md"

echo "=== Suspicious exit codes ==="
grep "subprocess died post-write" "$S/violations.md" 2>/dev/null | wc -l

echo "=== Total wall time ==="
python -c "
import re
cp = open('$S/pipeline_checkpoint.md').read()
total = sum(float(m.group(1)) for m in re.finditer(r'(\d+\.\d+)s', cp))
print(f'Total: {total:.0f}s ({total/60:.0f} min, {total/3600:.1f} hr)')
"
```

---

## SECTION N — CROSS-PHASE CONSISTENCY

```bash
echo "=== Finding flow ==="
python -c "
import re, glob
breadth = sum(len(re.findall(r'^##+ Finding', open(f).read(), re.M))
              for f in glob.glob('$S/analysis_*.md') if 'rescan' not in f and 'percontract' not in f)
inv = len(re.findall(r'[A-Z]+-\d+', open('$S/findings_inventory.md').read())) if __import__('os').path.exists('$S/findings_inventory.md') else 0
hyp = len(re.findall(r'^\\| H-', open('$S/hypotheses.md').read(), re.M)) if __import__('os').path.exists('$S/hypotheses.md') else 0
rpt = len(re.findall(r'^### \\[[CHMLI]-\\d+\\]', open('AUDIT_REPORT.md').read(), re.M)) if __import__('os').path.exists('AUDIT_REPORT.md') else 0
print(f'Breadth: {breadth} -> Inventory: {inv} -> Hypotheses: {hyp} -> Report: {rpt}')
drop = hyp - rpt if hyp > 0 and rpt > 0 else 'N/A'
print(f'Drop at assembly: {drop}')
"
```

**FAIL if**: Report sections significantly < hypotheses count (assembly dropped findings — Fix 3 regression).

---

## SECTION O — REGRESSION PATTERNS

```bash
echo "=== 13 regression checks ==="
echo "1. Unicode crash:"
python -c "
from pathlib import Path
bad = [p.name for p in Path('$S').glob('*.md') if True]  # Just check count
print(f'  {len(bad)} md files, all readable')
"

echo "2. skill_files empty:"
python -c "import json; d=json.load(open('$S/instantiation.json')); print(f'  skill_files: {len(d.get(\"skill_files\",[]))}')"

echo "3. niche_agents empty:"
python -c "import json; d=json.load(open('$S/instantiation.json')); print(f'  niche_agents: {len(d.get(\"niche_agents\",[]))}')"

echo "4. Ghost-phase (report_assemble idle):"
grep "report_assemble" "$S/pipeline_checkpoint.md"

echo "5. Tier writer >900s:"
grep "report_tiers" "$S/pipeline_checkpoint.md"

echo "6. Short-exit retries:"
grep "retries=2" "$S/pipeline_checkpoint.md" | head -3

echo "7. exit=1+PASS not logged:"
e1p=$(grep -c "exit=1" "$S/pipeline_checkpoint.md" 2>/dev/null)
logged=$(grep -c "subprocess died post-write" "$S/violations.md" 2>/dev/null)
echo "  exit=1 phases: $e1p, logged: $logged"

echo "8. Internal IDs in body:"
python -c "
import re
rpt = open('AUDIT_REPORT.md').read()
parts = re.split(r'(?=## Appendix A:)', rpt, maxsplit=1)
print(f'  {len(re.findall(r\"\[(?:CS|AC|TF|BLIND|EN|SE|VS|DEPTH|SLITHER|RS|PC|SP|DST|DE|DX|DS|DT)-[0-9]+\]\", parts[0]))}')" 2>/dev/null

echo "9. False unverified:"
grep "completeness" "$S/pipeline_checkpoint.md"

echo "10. percontract coverage:"
ls "$S"/analysis_percontract_*.md 2>/dev/null | wc -l

echo "11. depth_iter2 gate glob:"
grep "depth_iter2" "$S/violations.md" 2>/dev/null | grep -c "0 files"

echo "12. DA framing missing:"
grep -ciE "devil|adversarial" "$S/_prompt_depth_iter2.md" 2>/dev/null || echo "  N/A (iter2 may not have run)"

echo "13. Flag value check (MEDUSA false trigger):"
grep "MEDUSA_AVAILABLE" "$S/build_status.md" 2>/dev/null
grep "medusa_fuzz" "$S/pipeline_checkpoint.md"
```

---

## OUTPUT FORMAT

```markdown
# V2 Post-Optimization Assessment

## Configuration
- Mode / Language / Pipeline: {m} / {l} / {p}
- Wall time: {s}s ({min} min)
- Usage resets: {N}
- Phases: {N} run, {N} resumed
- Gate failures: {N}
- Violations: {N}

## SC Prebake: {PASS|FAIL|N/A|DEGRADED}
- Slither available: {Y/N}
- 6 flat files produced: {Y/N}
- Consumed by agents: {Y/N}
- If DEGRADED: reason (forge/slither not installed, compilation failed)

## Opus 4.8 Alignment: {PASS|ISSUES}
- Spawn mandates in prompts: {Y/N}
- Evidence tags mandatory: {Y/N}
- Evidence tag count: {N} (baseline: 326 in prior run)
- Agent count: expected {N}, actual {N}

## Chain Pre-Filter: {PASS|FAIL|N/A}
- Candidate pairs: {N} of {N} total
- Reduction: {%}
- Coverage of candidates: {%}

## Fix Verification
| # | Fix | Status |
|---|-----|--------|
| 1 | Skill injection | {PASS/FAIL} — skill_files: {N} |
| 2 | Niche agent metadata | {PASS/FAIL} — niche_agents: {N} |
| 3 | Ghost-skip staleness | {PASS/FAIL} — report_assemble: {duration}s, sections={N}/{summary} |
| 4 | Tier-writer timeout | {PASS/FAIL} — report_tiers: {duration}s |
| 5 | Short-exit guard | {PASS/FAIL} |
| 6 | exit=1+PASS logging | {PASS/FAIL} — {N} logged |
| 7 | Report scrubber | {PASS/FAIL} — IDs: {N}, metadata: {N} |
| 8 | Hypothesis parser | {PASS/FAIL} — queue: {total}/{remaining} |
| 9 | Gate glob fix | {PASS/FAIL} — iter2 "0 files" violations: {N} |
| 10 | DA routing | {PASS/FAIL} — adversarial keywords: {N} |
| 11 | Cumulative checkpoint | {PASS/FAIL} — resumed phases visible: {N} |
| 12 | Report gates artifact | {PASS/FAIL} — report_quality.md: {EXISTS/MISSING} |
| 13 | Uncertain cross-ref | {PASS/FAIL} — iter2 trigger correct: {Y/N} |
| 14 | Flag value check | {PASS/FAIL} — medusa trigger correct: {Y/N} |

## Regression Check (13 patterns)
| # | Pattern | Reoccurred? |
|---|---------|------------|
| 1-13 | ... | Y/N |

## Phase-by-Phase
| Phase | Status | Duration | Notes |
|-------|--------|----------|-------|
| ... | ... | ... | ... |

## Finding Flow
Breadth → Inventory → Hypotheses → Report: {N} → {N} → {N} → {N}
Drop at assembly: {N} (should be 0)

## New Failures
{Any issue not in the regression list}

## Recommendations
{Changes needed, or "Ship it" if clean}
```
