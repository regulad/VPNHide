# VPNHide

Per-app hiding of an on-device VPN interface from an iOS app's detection, on
roothide/Dopamine. VPNHide loads into every app but stays inert until you enable
it for a specific bundle ID from its Settings page; in an enabled app it
sanitizes the three interface-inference APIs an app uses to notice a VPN, so the
app believes it is on plain Wi-Fi while its traffic keeps routing through the
tunnel.

It hides the VPN's *enumeration*, not the tunnel. The kernel still routes through
the VPN — VPNHide only stops the target app from *seeing* the `utun`/`ipsec`
interface. Do not enable it for a VPN client itself: hiding the tunnel from the
app that owns it would break the connection.

## Threat model

The target is an app that refuses to run when it detects a VPN. On a Wi-Fi-only
device the app cannot fall back to another channel, so denying it the VPN
interface is enough. VPNHide addresses **on-device interface inference only** — an
app that additionally checks its exit IP against a VPN-reputation service server
side is out of scope (defeat that upstream of the device).

## How it works

All three detection paths read the kernel interface list and look for
tunnel-named entries (`utun`, `ipsec`, `ppp`, `tap`, `tun`). VPNHide hooks each:

- **`getifaddrs`** — unlinks VPN-named nodes from the returned list (safely: any
  non-head node is unlinked in place; `freeifaddrs` still frees the block via the
  unchanged head). If a tunnel is ever the head, its name is blanked instead.
- **`CFNetworkCopySystemProxySettings`** — strips VPN-named keys from the
  `__SCOPED__` sub-dictionary (which is keyed by interface name).
- **`nw_path_uses_interface_type`** — returns `false` for
  `nw_interface_type_other` (the type a VPN path reports); Wi-Fi/cellular/wired
  probes are untouched.
- **`nw_path_enumerate_interfaces`** — wraps the caller's block and skips VPN
  interfaces (and the `other` type) during enumeration.

Only tunnels match. `pdp_ip` (cellular), `en*`, `lo0`, and `awdl0` are never
touched.

### Self-gating without a rebuild

VPNHide ships a broad ElleKit filter (`VPNHide.plist`, `Classes = UIApplication`)
so it loads into every app, then decides at load time whether to install its
hooks by reading an enabled-bundle list. The Settings page writes that list; no
rebuild is needed to change which apps are covered.

Reading the list from inside a sandboxed app is the interesting part:

1. cfprefsd denies a foreign app the cross-domain `user-preference-read`, so
   `NSUserDefaults` on our domain comes back empty inside the target app.
2. Instead a [libSandy](https://github.com/roothide/libSandy) profile
   (`layout/Library/libSandy/VPNHide.plist`) grants a sandbox file-read extension
   on the prefs plist, applied in the tweak's constructor.
3. **roothide caveat:** the roothide libSandy fork runs `jbroot()` on the
   profile's `path` before issuing the extension (`sandyd/main.m`). So the grant
   lands on the *jbroot'd* path, and — because sandbox extensions match by path
   string — the tweak reads that same `jbroot("/var/mobile/.../xyz.regulad.vpnhide.plist")`
   path (the same pattern GeoShim uses). AltList writes the plist through cfprefsd
   to the real `/var/mobile` domain, which is the same underlying file, so the
   values the tweak reads are current.

The app picker itself is [AltList](https://github.com/opa334/AltList)'s
`ATLApplicationListMultiSelectionController` — the same multi-select controller
Choicy and Shadow use — driven entirely from `prefs/Resources/Root.plist`. With
`defaultApplicationSwitchValue = false`, the saved array is exactly the set of
apps switched on.

## Layout

| Path | Purpose |
|------|---------|
| `Tweak.x` | The hooks and the self-gate. |
| `VPNHide.plist` | ElleKit filter — loads into every app (`Classes = UIApplication`). |
| `layout/Library/libSandy/VPNHide.plist` | libSandy profile granting the prefs file-read extension. |
| `layout/Library/PreferenceLoader/Preferences/VPNHide.plist` | Settings entry. |
| `prefs/` | The Settings bundle (AltList picker). |
| `postinst` | Kills `Preferences` so the new Settings page appears without a respring. |

## Building

Requires [Theos](https://github.com/theos/theos) with the roothide SDK, plus the
`AltList` framework staged into Theos (run AltList's `install_to_theos.sh` once if
linking fails).

```sh
# development build (debug logging on)
make package

# release build (debug logging stripped)
make package FINALPACKAGE=1
```

Debug logging is compiled in for a normal build and stripped only when
`FINALPACKAGE=1`, matching the Theos convention. Install the `.deb` through Sileo
or `apt` (roothide dpkg) so the `.jbroot` symlinks resolve — not a bare
`dpkg -i`.

Runtime dependencies (declared in `control`): `ellekit`, `preferenceloader`,
`com.opa334.altlist`, `com.opa334.libsandy` (the roothide fork). libSandy's
`sandyd` daemon must be loaded — if `libSandy_applyProfile` returns non-zero,
bootstrap it with
`launchctl bootstrap system "$(jbroot /Library/LaunchDaemons/com.opa334.sandyd.plist)"`
or reboot.

## Using it

1. **Settings → VPNHide → Apps**, switch on the target app.
2. Relaunch the target app. Re-toggling takes effect on the app's next launch —
   an installed hook cannot be cleanly removed mid-run.
3. Connect your VPN and open the app; it should no longer see the tunnel.

Leave every VPN client switched **off**.

## Verifying

Build with debug logging (`make package`) and watch the log as the app launches:

```
[VPNHide] libSandy_applyProfile(VPNHide) = 0
[VPNHide] prefs: EnabledBundles=( "com.target.app" )
[VPNHide] enabled; hooks installed in TargetApp
[VPNHide] getifaddrs: hid 1 VPN interface entry
```

`libSandy_applyProfile = 0` means the prefs grant is in place; the
`EnabledBundles` line confirms the read; the `hid N` / `stripped N` lines confirm
the hooks are firing.

## Known limits

- **Exit-IP reputation** — an app that checks its outbound IP against a
  server-side VPN blocklist is unaffected. That has to be handled upstream of the
  device (e.g. a VPN whose exits aren't flagged).
- **Interface-name heuristics only** — detection based on something other than
  interface enumeration (routing tables, specific DNS behavior) is not covered.
- **Not system-wide by design** — VPNHide must be enabled per app and must never
  be enabled for a VPN client, whose tunnel it would break.

## License

[AGPLv3](LICENSE).
