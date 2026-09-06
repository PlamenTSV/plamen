---
description: Open the Plamen L1 infrastructure audit wizard in Codex.
argument-hint: [light|core|thorough] [project]
---

# plamen-l1-wizard

Arguments: `$ARGUMENTS`

Follow `~/.codex/skills/plamen/plamen-l1-wizard.md`. Do not ask a model-selection question.

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
