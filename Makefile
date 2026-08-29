export THEOS_PACKAGE_SCHEME = roothide

TARGET = iphone:latest:15.0
ARCHS = arm64

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = VPNHide
VPNHide_FILES = Tweak.x
VPNHide_CFLAGS = -fobjc-arc -Wall
VPNHide_FRAMEWORKS = Foundation CFNetwork Network
# libSandy - lifts the sandbox so the tweak can read its prefs plist inside a
# sandboxed app. Run libSandy's install_to_theos.sh once (like AltList).
VPNHide_LIBRARIES = sandy

# Debug logging is on for development builds and stripped only from a release
# build (make package FINALPACKAGE=1), matching the theos ecosystem convention.
ifneq ($(FINALPACKAGE),1)
VPNHide_CFLAGS += -DVH_DEBUG=1
endif

include $(THEOS_MAKE_PATH)/tweak.mk

SUBPROJECTS += prefs
include $(THEOS_MAKE_PATH)/aggregate.mk
