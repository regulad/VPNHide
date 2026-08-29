// VPNHide Settings page. The actual app picker is AltList's
// ATLApplicationListMultiSelectionController, driven entirely from Root.plist
// (same framework Choicy and Shadow use): it renders apps with icons, a search
// bar and User/System sections, and saves the enabled apps' bundle IDs to the
// EnabledBundles array in the xyz.regulad.vpnhide domain - the exact key the
// tweak self-gates on. So this controller only has to load that plist.

#import "VPNHideRootListController.h"

@implementation VPNHideRootListController

- (NSArray *)specifiers {
    if (!_specifiers) {
        _specifiers = [self loadSpecifiersFromPlistName:@"Root" target:self];
    }
    return _specifiers;
}

@end
