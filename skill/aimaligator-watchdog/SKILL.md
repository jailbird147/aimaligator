---
name: aimaligator-watchdog
display-name: AIMaligator Watchdog
description: Use when the user mentions AIMaligator, asks "any alerts?", reports a watchdog alert, or wants to accept or escalate file-change alerts.
---

# AIMaligator watchdog

AIMaligator is an alert-only watchdog for local AI assistants (Bionic, LM
Studio, Jan, Ollama, GPT4All, ...). It watches skill folders, app settings
and local model files, and alerts on changes. It never deletes or fixes
anything. Install it first if it is not present (see the AIMaligator
repository README).

## Key locations (default install)

- Program: `<install-dir>\.venv\Scripts\aimaligator.exe`
- Alerts log: `<install-dir>\state\alerts.log` (one event per line:
  `date time | kind | path | detail`)
- Config: `<install-dir>\config.json`
- Runs automatically every 5 minutes via a Windows scheduled task named
  "AIMaligator".

On this machine the install dir is `F:\AIMaligator` unless the user says
otherwise.

## How to respond

1. **"Any alerts?" / checking**: read the tail of `state/alerts.log`. If the
   user wants a fresh check, run
   `<install-dir>\.venv\Scripts\aimaligator.exe --once` and report the
   output. Summarise: how many alerts, what kind, and the exact path(s).
2. **User says a change WAS theirs**: run
   `<install-dir>\.venv\Scripts\aimaligator.exe --rebaseline`. Then confirm
   the log shows the alert resolved.
3. **User says it was NOT theirs**: do NOT rebaseline. The path is already
   known from the log; the user can answer "n" in an interactive console run
   (that launches a Defender scan and keeps alerting), or you may start a
   Defender scan of that exact path via
   `C:\Program Files\Windows Defender\MpCmdRun.exe -Scan -ScanType 3 -File <path>`
   after the user approves. Remind them to change passwords if anything
   actually malicious is confirmed.
4. **Adding something new to watch** (new model, new app folder): add the
   path to `watch_roots` in `config.json`, then run `--rebaseline` once and
   tell the user the baseline now includes it. Alternatively run `--init` to
   re-detect installed AI apps.

## Boundaries

- Never delete, quarantine, or "clean up" any flagged file - alert and
  escalate to the user's antivirus instead.
- Never run `--rebaseline` unless the user explicitly confirmed the changes
  were theirs. Rebaselining on an unconfirmed change whitewashes tampering.
- Do not edit `config.json` without telling the user what you are changing.
- Alert repetition is intentional (an unresolved change re-alerts every
  check). Do not silence it by other means.
