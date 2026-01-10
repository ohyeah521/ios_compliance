TARGET := iphone:clang:latest:14.0
INSTALL_TARGET_PROCESSES = SpringBoard

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = MonitorTweak

# 添加头文件搜索路径 添加当前目录到头文件搜索路径
MonitorTweak_CFLAGS = -fobjc-arc -I. -Imodule -Imodule/Symbol

# 2. 修正源文件列表：使用 += 来累加文件，不要重复直接赋值 (=)
MonitorTweak_FILES = Tweak.x \
                     MonitorHooks.x \
                     MonitorFiles.x \
                     MonitorUtils.m \
                     SDKDetector.m \
                     $(wildcard module/Symbol/*.m)

# 增加module/Symbol 目录下所有的 .m 文件
#MonitorTweak_FILES += $(wildcard module/Symbol/*.m)

# 框架引用：因为代码里用到了相册、通讯录、定位和keychain在这里声明
#MonitorTweak_FRAMEWORKS = UIKit Foundation AdSupport Photos Contacts CoreLocation Security
MonitorTweak_FRAMEWORKS = UIKit Foundation AdSupport

# 针对所有文件关闭“警告转错误”，并忽略特定的警告
MonitorTweak_CFLAGS += -Wall -Wno-format -Wno-error=constant-conversion  -Wno-error=int-conversion -Wno-error=constant-conversion -Wno-error=int-conversion -Wno-unused-but-set-variable -Wno-unused-variable -Wno-incompatible-pointer-types -O2


include $(THEOS_MAKE_PATH)/tweak.mk


