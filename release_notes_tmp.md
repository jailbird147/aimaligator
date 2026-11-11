AIMaligator 0.3.2

New: heartbeat - every check logs to state/checks.log, so a silenced or
crashed watchdog is visible as a gap in the 5-minute cadence.

New: baseline resets (rebaseline) now log a loud baseline-reset event to
the alerts log, since that is exactly the command an infected agent would
run to whitewash tampering.

deno.exe (Bionic's bundled runtime) added to the default allowed children.
