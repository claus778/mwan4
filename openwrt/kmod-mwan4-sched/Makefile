include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=kmod-mwan4-sched
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define KernelPackage/mwan4-sched
  SUBMENU:=Network Support
  TITLE:=MWAN4 per-flow real-time load-balancing scheduler
  DEPENDS:=+kmod-nf-conntrack +kmod-ipt-conntrack
  FILES:=$(PKG_BUILD_DIR)/mwan4_sched.ko
  AUTOLOAD:=$(call AutoLoad,60,mwan4_sched)
endef

define KernelPackage/mwan4-sched/description
  Lightweight Linux kernel Netfilter module for MWAN4 that performs
  lockless per-flow scheduling on IP_CT_NEW packets using real-time NIC
  throughput (Flow-Offload accurate), weighted burst deficit, and a
  latency-sensitive fast lane.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ../../kernel/mwan4_sched/mwan4_sched.c $(PKG_BUILD_DIR)/
	$(CP) ../../kernel/mwan4_sched/Makefile $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(KERNEL_MAKE) M="$(PKG_BUILD_DIR)" modules
endef

$(eval $(call KernelPackage,mwan4-sched))
