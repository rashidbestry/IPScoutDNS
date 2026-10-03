include $(TOPDIR)/rules.mk

PKG_NAME:=ipscoutdns
PKG_VERSION:=0.0.1
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

# Leave PKGARCH unset so the selected OpenWrt SDK assigns its target architecture.
include $(INCLUDE_DIR)/package.mk

define Package/ipscoutdns
	SECTION:=net
	CATEGORY:=Network
	TITLE:=IPScoutDNS filtering DNS service
	DEPENDS:=+ca-bundle
endef

define Package/ipscoutdns/description
DNS filtering service with upstream resolution and reachability checks.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./files/ipscoutdns $(PKG_BUILD_DIR)/ipscoutdns
	python3 ./generate-config.py ./files/ipscoutdns.conf $(PKG_BUILD_DIR)/ipscoutdns.conf \
		--active-domains-source ./files/active-domains.txt \
		--active-domains-destination $(PKG_BUILD_DIR)/active-domains.txt \
		--passive-domains-source ./files/passive-domains.txt \
		--passive-domains-destination $(PKG_BUILD_DIR)/passive-domains.txt
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/ipscoutdns/conffiles
/etc/ipscoutdns.conf
/etc/ipscoutdns/active-domains.txt
/etc/ipscoutdns/passive-domains.txt
endef

define Package/ipscoutdns/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ipscoutdns $(1)/usr/bin/ipscoutdns
	$(INSTALL_DIR) $(1)/etc/ipscoutdns
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/ipscoutdns.conf $(1)/etc/ipscoutdns.conf
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/active-domains.txt $(1)/etc/ipscoutdns/active-domains.txt
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/passive-domains.txt $(1)/etc/ipscoutdns/passive-domains.txt
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/ipscoutdns.init $(1)/etc/init.d/ipscoutdns
endef

$(eval $(call BuildPackage,ipscoutdns))
