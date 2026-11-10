# AIMaligator

An alert-only watchdog for your local AI assistant setup. It does **not**
delete, quarantine or fix anything — it watches, logs, and tells you, giving
you the exact path of anything suspicious. Your antivirus stays in charge of
actual removal.

## Why this exists

It started with a simple question: *how would we even know if the AI
assistant itself got compromised?* An agent that can browse the web,
download files and drive other apps is a tempting target - and a plain
antivirus has no idea what "normal" behaviour for an AI assistant looks
like. So we built a small, deliberately dumb sentinel that knows exactly
what normal is: a fingerprint of every file, program and network endpoint
the AI stack touches, and one rule - never act, only alert.

## Alternatives

There is a growing ecosystem, though none of these does quite the same job:

- **AgentSeal** (`agentseal`) - closest match. Scans skill files and MCP
  configs offline, and its `shield` mode watches agent config files in real
  time. Smarter than AIMaligator about file *contents* (it analyses skill
  text for prompt-injection patterns), but focused on coding agents and
  their MCP configs - it does not watch model weights, AI app settings,
  process children or network egress, and its shield mode auto-quarantines
  (AIMaligator deliberately never acts).
- **Snyk Agent Scan** (formerly `mcp-scan`), **Cisco MCP Scanner**,
  **MCP-Shield**, **NVIDIA SkillSpector** - strong on MCP servers and agent
  skills (prompt injection, tool poisoning). Several want API keys or cloud
  accounts; none watch model files or general app behaviour.
- **local-llm-configuration-auditor** - checks whether local AI servers are
  exposed/misconfigured on your network. A useful complement: AIMaligator
  watches changes, this audits setup.
- **Wazuh, Tripwire, AIDE** - classic file-integrity monitoring. Powerful but
  heavyweight, server-oriented, and they know nothing about AI apps - you
  would have to hand-craft every rule AIMaligator detects by default.

AIMaligator's niche: tiny, offline, no accounts, no API keys, Windows-simple,
and specifically knows the local AI stack (models, skills, settings,
processes, egress) while staying strictly alert-only.

## Installing on a machine

**Easiest:** download `AIMaligator-<version>-windows.zip` from this repo's
Releases page, unzip it, and run `install.ps1` from inside.

Or from a clone of this repository:

```cmd
powershell -ExecutionPolicy Bypass -File install.ps1
```

That finds Python, creates a virtual environment, installs the package
(offline from the bundled wheels when available), registers the 5-minute
scheduled task, then runs `aimaligator --init` — which auto-detects the AI
apps on that machine (LM Studio, Jan, Ollama, GPT4All, koboldcpp/llama.cpp
family), reads each app's own settings for its model folder, and takes the
first baseline. Pass `-InstallDir <path>` to install somewhere else.

## What it watches

1. **File tampering** — keeps a fingerprint of every file under the configured
   `watch_roots` (skill folders, LM Studio + Jan settings, and the local model
   folders of both apps). Small files get a full SHA-256 content hash; big
   files like model weights get a size + modification-time fingerprint, which
   is instant and still catches replacement, tampering or deletion.
   A new, changed or vanished file raises an alert with its full path.
2. **Child processes** — finds LM Studio / Bionic / Jan / Ollama processes
   and checks what programs they launch. Two policies (see `child_policy`
   in the config):
   - `suspicious-only` — alert when a launched program is on the
     `suspicious_children` blacklist (certutil, bitsadmin, mshta, ...)
   - `allowlist` — alert on ANY launched program not on the
     `allowed_children` list. Stricter; expect a few first-day prompts.
3. **Network egress** — alerts the first time an AI app process connects to
   a remote address it has never contacted before (local/link-local/
   multicast addresses are ignored). Endpoints are IP:port, not domains.
   Set `egress_watch: false` to disable. The first run builds the
   'known contacts' list silently, like the file baseline.
4. **Itself** — AIMaligator's own code, scripts and config are in the watch
   roots, so tampering with the watchdog raises an alert like anything else.

## Alerts

- Popup notification on your desktop (Windows toast)
- Written to `state/alerts.log` — one line per event:
  `2026-11-10 14:02:11 | changed-file | C:\...\SKILL.md | File contents changed`

## Running it

```cmd
F:\AIMaligator\.venv\Scripts\aimaligator.exe --once     :: one check, exit
F:\AIMaligator\.venv\Scripts\aimaligator.exe            :: watch continuously
F:\AIMaligator\.venv\Scripts\aimaligator.exe --init     :: re-detect AI apps, refresh config + baseline
F:\AIMaligator\.venv\Scripts\aimaligator.exe --rebaseline :: mark current state as known-good
```

The first ever run creates the baseline (your "known good" snapshot) and
reports it as an info event — no alerts for that first run.

**Supporting other apps (Ollama etc.):** you normally never edit the config
by hand — `--init` detects apps automatically and merges them in. New model
downloads appear as a one-time `new-file` alert; confirm it was you and the
baseline updates. Files that look like SSH/crypto keys are never opened
(some security software kills processes that touch them); they are tracked
by size + modified time only, which still catches tampering.

**When an alert fires and you are at the keyboard**, it asks one question:

- **"y" (it was you)** — the current file state becomes the new baseline
  automatically. No command needed.
- **"n" (it was NOT you)** — the suspicious path is handed to Windows
  Defender for a scan right away, the baseline stays old, and the alert
  repeats every check until you have dealt with it. The escalation is also
  written to the alerts log.

If nobody is at the keyboard (scheduled runs), alerts simply repeat until
someone answers. You can also accept changes headlessly at any time with
`aimaligator --rebaseline` — but only run that when you are sure the current
state is clean and yours.

## Suggested schedule

Run every 5 minutes with Windows Task Scheduler (see
`scripts/install-task.ps1`), or just run `aimaligator --once` whenever you
want a spot-check.

## What it cannot do

- Catch attacks between checks (a few minutes of blindness is normal)
- Detect brand-new malware — that is your antivirus's job
- See tampering that happens *while* it is not running
- Protect anything not listed in `config.json`

## Troubleshooting

**Checks suddenly stop / processes vanish:** on this setup, Malwarebytes 5.7
"APT Behaviour Protection" blocks and kills any process that *opens* SSH-key
files (verified 2026-11-10: `Exploit.T1003CredentialAccess`, MITRE T1003,
triggered by reading `id_ed25519.pub`). AIMaligator never opens key-like
files (SSH keys, `.pem/.key/.pfx/...`) — they are fingerprinted by size and
modified time only, so no exclusion is needed. Do not add one; the block was
correct behaviour.

## Companion skill

`skill/aimaligator-watchdog/SKILL.md` is a Claude/Bionic-style skill that
teaches an AI assistant how to operate AIMaligator (check alerts, accept
your own changes, escalate to Defender, add new watch roots). Copy that
folder into your assistant's skills directory if yours supports skills.

## Using with third-party antivirus / antimalware

AIMaligator is designed to sit *next to* whatever antivirus you prefer, not
replace it. It never removes, quarantines or repairs anything itself.

The only place a specific product is named is `scan_command` in the config,
which controls what happens when you answer "no" to an alert:

- `"defender"` (default) — launch a Windows Defender scan of the path
- `"none"` — just alert; you copy the path into your own scanner
- any other string — a command template containing `{path}`, e.g.
  `"C:\Program Files\YourAV\scanner.exe" /quick "{path}"`

Everything else (watching, alerting, logging, toasts) is product-neutral.
Note for dual-AV setups: two real-time engines can interfere with each other
and with scripts; see Troubleshooting for a real example.

## Tuning

All paths and the suspicious-program list live in `config.json` next to this
file. If alerts get noisy (e.g. LM Studio legitimately launches something
listed), remove that entry from `suspicious_children` and re-run.
