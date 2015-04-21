#
# Makefile for the Linux MPLS layer.
#

mpls-y := af_mpls.o mpls_if.o mpls_ilm.o mpls_init.o mpls_input.o \
	mpls_opcode.o mpls_nhlfe.o mpls_output.o \
	mpls_utils.o mpls_dst.o mpls_netlink.o mpls_proto.o \
	mpls_instr.o mpls_shim.o mpls_tunnel_here.o
mpls-$(CONFIG_SYSCTL) += mpls_sysctl.o
mpls-$(CONFIG_PROC_FS) += mpls_procfs.o

obj-$(CONFIG_MPLS) += mpls.o
#obj-$(CONFIG_MPLS_TUNNEL) += mpls_tunnel.o
