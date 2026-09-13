include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-mwan4
PKG_VERSION:=1.0.0
PKG_RELEASE:=1
PKG_MAINTAINER:=MWAN4 Team
PKG_LICENSE:=MIT

LUCI_TITLE:=LuCI support for MWAN4 multi-WAN failover & balancing
LUCI_DEPENDS:=+mwan4
LUCI_PKGARCH:=all

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
