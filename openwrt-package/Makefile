include $(TOPDIR)/rules.mk

PKG_NAME:=parental-control
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/parental-control
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Recovered parental control service and web UI
  DEPENDS:=+libjson-c +conntrack
endef

define Package/parental-control/description
 Reconstructed parental-control daemon and web frontend recovered from installed binaries.
endef

define Package/parental-control/conffiles
/etc/parental-control/devices.json
/etc/parental-control/settings.json
endef

define Build/Prepare
	$(call Build/Prepare/Default)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) -Wall -Wextra -Werror $(TARGET_LDFLAGS) -o $(PKG_BUILD_DIR)/parental-control $(PKG_BUILD_DIR)/parental-control.c $(PKG_BUILD_DIR)/parental-control-web.c -ljson-c -pthread
endef

define Package/parental-control/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/init.d $(1)/etc/parental-control $(1)/usr/share/parental-control/www
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/parental-control $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/etc/init.d/parental-control $(1)/etc/init.d/
	$(INSTALL_CONF) ./files/etc/parental-control/settings.json $(1)/etc/parental-control/
	$(INSTALL_CONF) ./files/etc/parental-control/devices.default.json $(1)/etc/parental-control/devices.json
	$(INSTALL_CONF) ./files/etc/parental-control/devices.example.json $(1)/etc/parental-control/devices.example.json
	$(CP) ./files/usr/share/parental-control/www/* $(1)/usr/share/parental-control/www/
endef

$(eval $(call BuildPackage,parental-control))
