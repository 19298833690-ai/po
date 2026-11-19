ARCHS = arm64
TARGET = iphone:clang:16.5:15.0
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = po
po_FILES = Tweak.xm
po_CFLAGS = -fobjc-arc -Wno-deprecated-declarations
po_FRAMEWORKS = Foundation

include $(THEOS_MAKE_PATH)/tweak.mk
