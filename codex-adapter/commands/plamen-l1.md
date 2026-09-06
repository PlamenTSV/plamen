---
description: Launch or resume a Plamen L1 infrastructure audit through the deterministic driver.
argument-hint: [light|core|thorough|resume] [project-or-config]
---

# plamen-l1

Arguments: `$ARGUMENTS`

Follow `~/.codex/skills/plamen/SKILL.md` with the L1 wizard reference. New configs must set `pipeline = l1` and `cli_backend = codex`.

Do not manually orchestrate Plamen phases and do not spawn audit agents yourself.
Launch only the shared Python driver:

```
plamen resume "{CONFIG_PATH}"
```

New run (only with a new config pointing at a distinct clean destination;
never reuse or modify an existing run root):

```
plamen start-config "{NEW_CONFIG_PATH}"
```
