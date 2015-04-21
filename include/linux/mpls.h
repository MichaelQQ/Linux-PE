/*****************************************************************************
 * MPLS
 *      An implementation of the MPLS (MultiProtocol Label
 *      Switching Architecture) for Linux.
 *
 * Authors:
 *          James Leu        <jleu@mindspring.com>
 *          Ramon Casellas   <casellas@infres.enst.fr>
 *
 *   (c) 1999-2004   James Leu        <jleu@mindspring.com>
 *   (c) 2003-2004   Ramon Casellas   <casellas@infres.enst.fr>
 *
 * include/linux/mpls.h
 *      Data types and structs used by userspace programs to access MPLS
 *      forwarding. Most interface with the MPLS subsystem is IOCTL based
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 ****************************************************************************/

#ifndef _LINUX_MPLS_H_
#define _LINUX_MPLS_H_

#ifdef __KERNEL__
#include <linux/socket.h>
#include <linux/if.h>
#else
#include <sys/socket.h>
#include <linux/types.h>
#include <net/if.h>
#endif

#define MPLS_NUM_OPS		8

#define MPLS_LINUX_VERSION	0x01090800

#define	MPLS_GRP_ILM	1
#define	MPLS_GRP_NHLFE	2
#define	MPLS_GRP_XC	4
#define	MPLS_GRP_LABELSPACE 8
#define	MPLS_GRP_TUNNEL 16

#define MPLS_IPV4_EXPLICIT_NULL	0       /* only valid as sole label stack entry
					   Pop label and send to IPv4 stack */
#define MPLS_ROUTER_ALERT	1       /* anywhere except bottom, packet it is
					   forwared to a software module
					   determined by the next label,
					   if the packet is forwarded, push this
					   label back on */
#define MPLS_IPV6_EXPLICIT_NULL	2       /* only valid as sole label stack entry
					   Pop label and send to IPv6 stack */
#define MPLS_IMPLICIT_NULL	3       /* a LIB with this, signifies to pop
					   the next label and use that */

#define MPLS_CHANGE_MTU		0x01
#define MPLS_CHANGE_PROP_TTL	0x02
#define MPLS_CHANGE_INSTR	0x04
#define MPLS_CHANGE_PROTO	0x10

enum mpls_dir {
	MPLS_IN = 0x10,
	MPLS_OUT = 0x20
};

enum mpls_opcode_enum {
	MPLS_OP_NOP = 0x00,
	MPLS_OP_POP,
	MPLS_OP_PEEK,
	MPLS_OP_PUSH,
	MPLS_OP_DLV,
	MPLS_OP_FWD,
	MPLS_OP_NF_FWD,
	MPLS_OP_DS_FWD,
	MPLS_OP_EXP_FWD,
	MPLS_OP_SET,
	MPLS_OP_SET_RX,
	MPLS_OP_SET_TC,
	MPLS_OP_SET_DS,
	MPLS_OP_SET_EXP,
	MPLS_OP_EXP2TC,
	MPLS_OP_EXP2DS,
	MPLS_OP_TC2EXP,
	MPLS_OP_DS2EXP,
	MPLS_OP_NF2EXP,
	MPLS_OP_SET_NF,
	MPLS_OP_MAX
};

enum mpls_label_type_enum {
	MPLS_LABEL_GEN = 1,
	MPLS_LABEL_ATM,
	MPLS_LABEL_FR,
	MPLS_LABEL_KEY
};

#define MPLS_SHIM_SIZE 4

struct mpls_label_atm {
	u_int16_t  mla_vpi;
	u_int16_t  mla_vci;
};

struct mpls_label {
	enum mpls_label_type_enum ml_type;
	union {
		u_int32_t ml_key;
		u_int32_t ml_gen;
		u_int32_t ml_fr;
		struct mpls_label_atm ml_atm;
	} u;
	int ml_index;
};

struct mpls_in_label_req {
	unsigned int      mil_proto;
	struct mpls_label mil_label;
	unsigned char     mil_change_flag;
};

#define MPLS_LABELSPACE_MAX	255

struct mpls_labelspace_req {
	int mls_ifindex;                  /* Index to the MPLS-enab. interface*/
	int mls_labelspace;               /* Labelspace IN/SET -- OUT/GET     */
};

struct mpls_nexthop_info {
	unsigned int    mni_if;
	struct sockaddr mni_addr;
};

struct mpls_out_label_req {
	struct mpls_label mol_label;
	u_int32_t         mol_mtu;
	int8_t            mol_propagate_ttl;
	unsigned char     mol_change_flag;
};

struct mpls_xconnect_req {
	struct mpls_label mx_in;
	struct mpls_label mx_out;
};

struct mpls_tunnel_req {
	char mt_ifname[IFNAMSIZ];
	unsigned int mt_nhlfe_key;
};

#define MPLS_NFMARK_NUM 64

struct mpls_nfmark_fwd {
	unsigned int nf_key[MPLS_NFMARK_NUM];
	unsigned short nf_mask;
};

#define MPLS_DSMARK_NUM 64

struct mpls_dsmark_fwd {
	unsigned int df_key[MPLS_DSMARK_NUM];
	unsigned char df_mask;
};

#define MPLS_TCINDEX_NUM 64

struct mpls_tcindex_fwd {
	unsigned int tc_key[MPLS_TCINDEX_NUM];
	unsigned short tc_mask;
};

#define MPLS_EXP_NUM 8

struct mpls_exp_fwd {
	unsigned int ef_key[MPLS_EXP_NUM];
};

struct mpls_exp2tcindex {
	unsigned short e2t[MPLS_EXP_NUM];
};

struct mpls_exp2dsmark {
	unsigned char e2d[MPLS_EXP_NUM];
};

struct mpls_tcindex2exp {
	unsigned char t2e_mask;
	unsigned char t2e[MPLS_TCINDEX_NUM];
};

struct mpls_dsmark2exp {
	unsigned char d2e_mask;
	unsigned char d2e[MPLS_DSMARK_NUM];
};

struct mpls_nfmark2exp {
	unsigned char n2e_mask;
	unsigned char n2e[MPLS_NFMARK_NUM];
};

struct mpls_instr_elem {
	unsigned short mir_opcode;
	unsigned char mir_direction;
	union {
		struct mpls_label        push;
		struct mpls_label        fwd;
		struct mpls_nfmark_fwd   nf_fwd;
		struct mpls_dsmark_fwd   ds_fwd;
		struct mpls_exp_fwd      exp_fwd;
		struct mpls_nexthop_info set;
		unsigned int             set_rx;
		unsigned short           set_tc;
		unsigned short           set_ds;
		unsigned char            set_exp;
		struct mpls_exp2tcindex  exp2tc;
		struct mpls_exp2dsmark   exp2ds;
		struct mpls_tcindex2exp  tc2exp;
		struct mpls_dsmark2exp   ds2exp;
		struct mpls_nfmark2exp   nf2exp;
		unsigned long            set_nf;
	} mir_data;
};

/* Standard shortcuts */
#define mir_push       mir_data.push
#define mir_fwd        mir_data.fwd
#define mir_nf_fwd     mir_data.nf_fwd
#define mir_ds_fwd     mir_data.ds_fwd
#define mir_exp_fwd    mir_data.exp_fwd
#define mir_set        mir_data.set
#define mir_set_rx     mir_data.set_rx
#define mir_set_tc     mir_data.set_tc
#define mir_set_tx     mir_data.set_tx
#define mir_set_ds     mir_data.set_ds
#define mir_set_exp    mir_data.set_exp
#define mir_set_nf     mir_data.set_nf
#define mir_exp2tc     mir_data.exp2tc
#define mir_exp2ds     mir_data.exp2ds
#define mir_tc2exp     mir_data.tc2exp
#define mir_ds2exp     mir_data.ds2exp
#define mir_nf2exp     mir_data.nf2exp

struct mpls_instr_req {
	struct mpls_instr_elem       mir_instr[MPLS_NUM_OPS];
	unsigned char                mir_instr_length;
	unsigned char                mir_direction;
	int                          mir_index;
	struct mpls_label            mir_label;
};

#endif

