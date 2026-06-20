#!/usr/bin/env bash
# plamen monitor — periodic status heartbeat for a running plamen V2 audit.
#
# Usage:   plamen_monitor.sh <scratchpad_dir> [interval_minutes]
# Example: plamen_monitor.sh /path/to/project/.scratchpad 15
#
# Designed to be armed via the Claude Code `Monitor` tool: every stdout line
# becomes a chat notification. CLAUDE BACKEND ONLY — `Monitor` is a Claude Code
# harness tool with no Codex (`codex exec`) equivalent.
#
# It reads ONLY artifacts the driver already writes:
#   _v2_checkpoint.json   — completed-phase list
#   _stdio_*.log          — per-worker stdio (freshness = liveness proxy)
#   _plamen.log           — driver log tail
#   ../AUDIT_REPORT.md     — terminal success marker
#
# Emits: an immediate report on arm, then one heartbeat every <interval>;
# plus event-driven PROGRESS / ALERT-STALL lines, and a terminal DONE /
# ALERT-DEAD when the driver process exits.
set -u

S="${1:?usage: plamen_monitor.sh <scratchpad_dir> [interval_minutes]}"
MIN="${2:-15}"
case "$MIN" in (*[!0-9]*|"") MIN=15 ;; esac
[ "$MIN" -lt 1 ] 2>/dev/null && MIN=15
HB=$(( MIN * 60 ))
R="$(dirname "$S")/AUDIT_REPORT.md"   # AUDIT_REPORT.md sits beside .scratchpad

# Wait up to 3 min for the driver to appear (arming before/with launch is fine).
g=0
while [ $g -lt 36 ]; do
  pgrep -f scripts/plamen_driver >/dev/null 2>&1 && break
  g=$((g+1)); sleep 5
done
echo "$(date +%H:%M:%S) monitor armed @${MIN}m (driver $(pgrep -f scripts/plamen_driver >/dev/null 2>&1 && echo up || echo NOT-up))"

prevphase=""; alerted=0; last_hb=0
while true; do
  now=$(date +%s); ts=$(date +%H:%M:%S)

  # Terminal: driver gone.
  if ! pgrep -f scripts/plamen_driver >/dev/null 2>&1; then
    if [ -f "$R" ]; then
      echo "$ts DONE: driver exited, AUDIT_REPORT.md present — audit complete."
    else
      echo "$ts ALERT-DEAD: driver gone, no AUDIT_REPORT.md — died/stopped, investigate."
    fi
    break
  fi

  phase=$(python3 -c "import json;print(json.load(open('$S/_v2_checkpoint.json')).get('completed'))" 2>/dev/null || echo '?')
  newest=$(ls -t "$S"/_stdio_*.log 2>/dev/null | head -1)
  if [ -n "$newest" ]; then
    nm=$(stat -c %Y "$newest" 2>/dev/null || echo "$now")
    nsize=$(wc -c <"$newest" 2>/dev/null || echo 0)
  else
    nm=$now; nsize=0
  fi
  nm_age=$(( now - nm ))
  last=$(tail -1 "$S/_plamen.log" 2>/dev/null | sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g' | cut -c1-80)

  # Event: phase progressed.
  if [ "$phase" != "$prevphase" ] && [ -n "$prevphase" ]; then
    echo "$ts PROGRESS: completed=$phase"; alerted=0
  fi
  prevphase=$phase

  # Event: worker stdio gone quiet (small file >5min, or any file >9min) → likely stuck.
  if [ $alerted -eq 0 ] && { { [ "$nsize" -lt 2500 ] && [ $nm_age -gt 300 ]; } || [ $nm_age -gt 540 ]; }; then
    echo "$ts ALERT-STALL: completed=$phase | newest worker stdio idle ${nm_age}s (size ${nsize}B) — likely stuck. last: $last"
    alerted=1
  fi
  [ $nm_age -lt 120 ] && alerted=0   # reset stall latch once activity resumes

  # Heartbeat: immediately on arm, then every <interval>.
  if [ $(( now - last_hb )) -ge $HB ]; then
    echo "$ts ok: completed=$phase | worker_idle=${nm_age}s | newest=${nsize}B | last: $last"
    last_hb=$now
  fi

  sleep 60
done
