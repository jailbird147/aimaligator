AIMaligator 0.3.3

New: exclude_globs config key - build junk (__pycache__, egg-info, .pyc)
no longer triggers alerts.

New: escalation now works with third-party antiviruses. When one is
registered, Windows disables Defender; AIMaligator detects that and reports
it honestly instead of failing. scan_command accepts any scanner command
template containing {path} - the README includes a working Avast ashQuick
example.
