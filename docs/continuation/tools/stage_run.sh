#!/bin/sh
# Stage a new DODO validation run byte-identical to run41's audited source.
# Usage: SRC=run42 RUN=run44 sh docs/continuation/tools/stage_run.sh
set -eu
: "${RUN:?set RUN=runNN}"; SRC="${SRC:-run42}"
S=/Users/ptsanev/dodo-v3-validation-$SRC; D=/Users/ptsanev/dodo-v3-validation-$RUN
[ -e "$D" ] && { echo "$D exists"; exit 2; }
mkdir -p "$D/omni-chain-contracts/.scratchpad"
rsync -a --exclude '.scratchpad' --exclude '.DS_Store' "$S/omni-chain-contracts/" "$D/omni-chain-contracts/"
cp "$S/README.md" "$D/README.md"
python3 - "$S" "$D" "$SRC" "$RUN" <<'PY'
import json, sys; from pathlib import Path
S, D, src, run = sys.argv[1:5]
d = json.loads(Path(f"{S}/omni-chain-contracts/.scratchpad/config.json").read_text())
for k in ("project_root", "scratchpad", "docs_path"): d[k] = d[k].replace(src, run)
assert all(src not in str(v) for v in d.values())
Path(f"{D}/omni-chain-contracts/.scratchpad/config.json").write_text(json.dumps(d, indent=2, sort_keys=True) + "\n")
print("config written")
PY
diff -rq "$S/omni-chain-contracts" "$D/omni-chain-contracts" -x .scratchpad -x .DS_Store >/dev/null && echo "$RUN staged byte-identical to $SRC"
