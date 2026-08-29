include $(THEOS)/makefiles/common.mk

BUNDLE_NAME = VPNHidePrefs
VPNHidePrefs_FILES = VPNHideRootListController.m
VPNHidePrefs_INSTALL_PATH = /Library/PreferenceBundles
VPNHidePrefs_CFLAGS = -fobjc-arc
VPNHidePrefs_FRAMEWORKS = UIKit
VPNHidePrefs_PRIVATE_FRAMEWORKS = Preferences
# AltList provides the app picker (ATLApplicationListMultiSelectionController).
# roothide bundles it in theos; if linking fails, run AltList's
# install_to_theos.sh once. Runtime dependency declared in ../control.
VPNHidePrefs_EXTRA_FRAMEWORKS = AltList

include $(THEOS_MAKE_PATH)/bundle.mk
