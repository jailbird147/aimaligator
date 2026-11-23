AIMaligator 0.4.0

New: silent_notifications config switch - toasts without sound.

New: auto_scan config switch - suspicious paths are handed to the
configured antivirus automatically (each file version scanned once, no
repeat spam). Accepting changes into the baseline still requires a human.

Also: toast text/paths in notifications, dedup of auto-scans across
cycles, and auto-scanned memory resets when a baseline is accepted.
