# Lessons learned

What building AIMaligator taught us - kept here so we don't have to learn
it twice.

1. **Ask the security question early.** "How would I even know if I was
   being attacked?" produced a real tool; most people never ask it.
2. **The AI agent is the attack surface.** A process with internet access,
   download rights and app control doesn't need a virus to do damage.
3. **Alert-only is a feature.** A watchdog that never deletes or "fixes"
   anything cannot be turned into a weapon against the system it guards.
4. **Only the human can update the baseline.** Silently absorbing changes
   after one alert would let tampering alert exactly once and then vanish.
5. **Test against the real thing.** Every fake-object test passed while the
   first real psutil call crashed the process watch. And a toast title with
   parentheses in it killed PowerShell outright.
6. **Your own security software is a suspect - and usually right.**
   Malwarebytes killed our scanner repeatedly; every block was a legitimate
   verdict on what it could see. We designed around it instead of
   weakening it. (And: two real-time AVs at once causes phantom behaviour.)
7. **A stale process is a security hole.** A watchdog running with an old
   config in memory can silently unwatch new things. Re-read state every
   cycle; re-read it again before acting on a human's decision.
8. **Never open what you don't need to read.** Fingerprinting SSH keys by
   size+mtime protects the user's secrets *and* avoids fights with
   key-protection software - same fix, two reasons.
9. **Say the quiet part out loud.** The README documents our own bugs,
   false alarms and unproven corners. Trust is built by admitting limits.
