CLEANFILES += \
	vswitchd/ovs-brcompatd.8

sbin_PROGRAMS += vswitchd/ovs-brcompatd
vswitchd_ovs_brcompatd_SOURCES = \
	vswitchd/ovs-brcompatd.c
vswitchd_ovs_brcompatd_LDADD = -lopenvswitch $(SSL_LIBS)
MAN_ROOTS += vswitchd/ovs-brcompatd.8.in
