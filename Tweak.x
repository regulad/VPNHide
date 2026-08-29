// VPNHide - hide an on-device VPN interface from ONE target app's detection.
//
// The target imports getifaddrs, CFNetworkCopySystemProxySettings, and the
// nw_path_* family. All three are interface-inference: they read the kernel's
// interface list and look for VPN-named entries (utun/ipsec/ppp/...). This tweak
// sanitizes each so the app never sees the VPN interface. Traffic still routes
// through the VPN at the kernel level - we only hide the *enumeration*, so the
// app keeps working over the tunnel while believing it is on plain Wi-Fi.
//
// The tweak loads into every app (broad filter) but self-gates: it only installs
// its hooks for apps the user enabled in Settings, so it is inert everywhere by
// default and can never break a VPN client it was not turned on for. Never enable
// it for a VPN client itself - hiding utun from the tunnel's own app would break
// the tunnel.

#import <Foundation/Foundation.h>
#import <ifaddrs.h>
#import <string.h>
#import <CFNetwork/CFNetwork.h>
#import <Network/Network.h>
// jbroot() maps a jbroot-relative path to the real absolute path under roothide's
// randomized root, resolved at runtime via the binary's own .jbroot symlink. Same
// pattern GeoShim uses; no libroothide link needed.
#import <roothide.h>

#ifdef VH_DEBUG
#define VHLog(fmt, ...) NSLog(@"[VPNHide] " fmt, ##__VA_ARGS__)
#else
#define VHLog(fmt, ...) do { if (0) NSLog(@"[VPNHide] " fmt, ##__VA_ARGS__); } while (0)
#endif

// Interface-name prefixes that indicate a VPN/tunnel. pdp_ip (cellular) and
// en/lo/awdl are deliberately NOT here - only tunnels are hidden.
static BOOL vh_is_vpn_name(const char *name) {
    if (!name || !name[0]) return NO;
    static const char *prefixes[] = { "utun", "ipsec", "ppp", "tap", "tun" };
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        size_t n = strlen(prefixes[i]);
        if (strncmp(name, prefixes[i], n) == 0) return YES;
    }
    return NO;
}

// Reading the enable-list from inside a sandboxed app: cfprefsd denies the
// cross-domain "user-preference-read", so NSUserDefaults on our domain comes back
// empty in a foreign app. Instead the libSandy "VPNHide" profile (applied in
// %ctor) grants a sandbox file-read extension on the prefs plist, and we read the
// file directly. The roothide libSandy fork runs jbroot() on the profile path
// before issuing the extension (sandyd/main.m), so the grant - and therefore our
// read - use the jbroot'd path; sandbox extensions match by path string. AltList
// writes the plist through cfprefsd to the real /var/mobile domain, which is the
// same underlying file, so the values we read are current. Same jbroot() prefs
// pattern GeoShim uses.
#define kVHPrefsPath (jbroot(@"/var/mobile/Library/Preferences/xyz.regulad.vpnhide.plist"))

// From libSandy (com.opa334.libsandy). Declared inline so no header install is
// needed; linked via VPNHide_LIBRARIES = sandy.
extern int libSandy_applyProfile(const char *profileName);

static NSArray<NSString *> *vh_enabled_bundles(void) {
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:kVHPrefsPath];
    if (!d) {
        VHLog(@"prefs: could not read %@ (libSandy profile not applied?)", kVHPrefsPath);
        return @[];
    }
    id v = d[@"EnabledBundles"];
    if (![v isKindOfClass:[NSArray class]]) return @[];
    VHLog(@"prefs: EnabledBundles=%@", v);
    return v;
}

static BOOL vh_enabled_for_current_app(void) {
    NSString *bid = NSBundle.mainBundle.bundleIdentifier;
    if (bid.length == 0) return NO;
    return [vh_enabled_bundles() containsObject:bid];
}

%group VPNHooks

#pragma mark - getifaddrs

// getifaddrs on Darwin returns a single malloc'd block; freeifaddrs frees the
// head pointer. So it is safe to unlink any NON-head node (the block is still
// freed via the unchanged head, and the unlinked node lives inside it). If a
// VPN interface is ever the head (almost never - lo0 is first), we blank its
// name in place instead of moving the head, which would corrupt freeifaddrs.
%hookf(int, getifaddrs, struct ifaddrs **ifap) {
    int ret = %orig(ifap);
    if (ret != 0 || !ifap || !*ifap) return ret;

    int hidden = 0;
    struct ifaddrs *cur = *ifap, *prev = NULL;
    while (cur) {
        if (vh_is_vpn_name(cur->ifa_name)) {
            hidden++;
            if (prev) {
                prev->ifa_next = cur->ifa_next;   // safe unlink (non-head)
                cur = cur->ifa_next;
                continue;
            } else if (cur->ifa_name) {
                cur->ifa_name[0] = '\0';           // head fallback: blank the name
            }
        }
        prev = cur;
        cur = cur->ifa_next;
    }
    if (hidden) VHLog(@"getifaddrs: hid %d VPN interface entr%s", hidden, hidden == 1 ? "y" : "ies");
    return ret;
}

#pragma mark - CFNetworkCopySystemProxySettings

// The __SCOPED__ sub-dictionary is keyed by interface name; strip VPN-named keys.
%hookf(CFDictionaryRef, CFNetworkCopySystemProxySettings) {
    CFDictionaryRef orig = %orig();
    if (!orig) return orig;

    CFMutableDictionaryRef m = CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, orig);
    CFRelease(orig);
    if (!m) return NULL;

    CFTypeRef scoped = CFDictionaryGetValue(m, CFSTR("__SCOPED__"));
    if (scoped && CFGetTypeID(scoped) == CFDictionaryGetTypeID()) {
        CFMutableDictionaryRef ms =
            CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, (CFDictionaryRef)scoped);
        CFIndex n = CFDictionaryGetCount(ms);
        if (n > 0) {
            const void **keys = malloc(sizeof(void *) * n);
            CFDictionaryGetKeysAndValues(ms, keys, NULL);
            int removed = 0;
            for (CFIndex i = 0; i < n; i++) {
                CFStringRef key = (CFStringRef)keys[i];
                char buf[256];
                if (CFStringGetCString(key, buf, sizeof(buf), kCFStringEncodingUTF8) &&
                    vh_is_vpn_name(buf)) {
                    CFDictionaryRemoveValue(ms, key);
                    removed++;
                }
            }
            free(keys);
            if (removed) VHLog(@"proxy: stripped %d scoped VPN key(s)", removed);
        }
        CFDictionarySetValue(m, CFSTR("__SCOPED__"), ms);
        CFRelease(ms);
    }
    return m;   // caller owns and releases (Copy rule)
}

#pragma mark - NWPath

// A VPN path reports interface type "other". Deny that specifically; connectivity
// checks look at wifi/cellular/wired, so this only affects VPN probing.
%hookf(bool, nw_path_uses_interface_type, nw_path_t path, nw_interface_type_t type) {
    if (type == nw_interface_type_other) {
        VHLog(@"nw_path_uses_interface_type(other) -> false");
        return false;
    }
    return %orig(path, type);
}

// Skip VPN interfaces (and the "other" type) when the app enumerates the path.
%hookf(void, nw_path_enumerate_interfaces, nw_path_t path, nw_path_enumerate_interfaces_block_t block) {
    // Assign the wrapper to a variable first: logos' %orig parser cannot handle
    // a block literal passed directly as a %orig argument.
    nw_path_enumerate_interfaces_block_t wrapper = ^bool(nw_interface_t iface) {
        const char *name = nw_interface_get_name(iface);
        if (vh_is_vpn_name(name) || nw_interface_get_type(iface) == nw_interface_type_other) {
            return true;   // continue enumeration, but don't show this one to the app
        }
        return block(iface);
    };
    %orig(path, wrapper);
}

%end   // %group VPNHooks

%ctor {
    @autoreleasepool {
        // Lift the sandbox so we can read the prefs plist from inside this app.
        // Must precede the prefs read below.
        int sandy = libSandy_applyProfile("VPNHide");
        VHLog(@"libSandy_applyProfile(VPNHide) = %d", sandy);

        // Self-gate: the broad filter loads us into every app, but we only hook
        // where the user enabled it. Re-toggling in Settings takes effect on the
        // app's next launch (an installed %hookf cannot be cleanly removed).
        if (vh_enabled_for_current_app()) {
            %init(VPNHooks);
            VHLog(@"enabled; hooks installed in %@", NSProcessInfo.processInfo.processName);
        } else {
            VHLog(@"idle in %@ (not in EnabledBundles)", NSProcessInfo.processInfo.processName);
        }
    }
}
