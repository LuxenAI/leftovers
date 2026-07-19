################################################################################
# Leftovers guest supervisor
################################################################################

LEFTOVERS_GUEST_SUPERVISOR_VERSION = 1
LEFTOVERS_GUEST_SUPERVISOR_SITE = $(BR2_EXTERNAL_LEFTOVERS_GUEST_PATH)/package/leftovers-guest-supervisor/src
LEFTOVERS_GUEST_SUPERVISOR_SITE_METHOD = local
LEFTOVERS_GUEST_SUPERVISOR_LICENSE = Apache-2.0
LEFTOVERS_GUEST_SUPERVISOR_LICENSE_FILES = LICENSE

define LEFTOVERS_GUEST_SUPERVISOR_BUILD_CMDS
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_LDFLAGS) -std=c11 -D_GNU_SOURCE \
		-Wall -Wextra -Werror -Wformat=2 -Wformat-security -Wshadow -Wconversion \
		-Wstrict-prototypes -fstack-protector-strong -fPIE -pie \
		-o $(@D)/leftovers-guest-supervisor $(@D)/guest_supervisor.c
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_LDFLAGS) -std=c11 -D_GNU_SOURCE \
		-Wall -Wextra -Werror -Wformat=2 -Wformat-security -Wshadow -Wconversion \
		-Wstrict-prototypes -fstack-protector-strong -fPIE -pie \
		-o $(@D)/leftovers-early-init $(@D)/early_init.c
endef

define LEFTOVERS_GUEST_SUPERVISOR_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(@D)/leftovers-guest-supervisor \
		$(TARGET_DIR)/sbin/leftovers-guest-supervisor
	$(INSTALL) -D -m 0755 $(@D)/leftovers-early-init $(TARGET_DIR)/init
endef

$(eval $(generic-package))
