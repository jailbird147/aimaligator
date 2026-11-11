AIMaligator 0.3.1

New: when a watched file changes, the watchdog keeps the old version and
writes a unified diff to state/changed-backups/. Run "aimaligator --diff"
to see exactly what changed before deciding whether it was yours.

Also: change backups are taken once per change (no repeat spam), big files
and key files are tracked without reading their contents, and the installer
now installs from source when cloning the repo without wheels.
