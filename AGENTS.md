# Agent notes for `regulad/VPNHide`

This repository is VPNHide, a roothide tweak that hides an on-device VPN
interface from chosen iOS apps. [README.md](README.md) explains how it reads
its settings through libSandy.

## Debugging the libSandy grant

- `libSandy_applyProfile()` returning 0 proves a token was consumed, not that
  the read works. Call `libSandy_works()` after it, never before.
- If `libSandy_works()` is 1 and `libSandy_applyProfile()` is 0 but the read
  fails, the paths don't match: `open()` the file and check for `EPERM`, then
  read the `jbroot()`'d path.
- After changing a profile, restart sandyd:
  `launchctl kickstart -k system/com.opa334.sandyd`.
- The AltList picker writes the real `/var/mobile` domain through cfprefsd.
  Never write the `jbroot()`'d path directly.
