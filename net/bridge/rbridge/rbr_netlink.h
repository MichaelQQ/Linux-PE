/*
 *	Generic parts
 *	Linux ethernet Rbridge
 *
 *	Authors:
 *	Ahmed AMAMOU	<ahmed@gandi.net>
 *	Kamel Haddadou	<kamel@gandi.net>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#ifndef RBR_NETLINK_H_
#define RBR_NETLINK_H_
#include "rbr_private.h"

/*TRILL Generic Netlink attributes definition*/
#define TRILL_NL_VERSION 0x1
#define TRILL_NL_FAMILY  "TRILL_NL"
#define TRILL_MCAST_NAME "TR_NL_MCAST"
#include "rbr_private.h"

struct trill_nl_header {
	int ifindex;  /* port id */
	int total_length; /* message total length for mutipart messages check */
	int msg_number; /* message number for multipart messages check */
};

enum {
	TRILL_ATTR_UNSPEC,
	TRILL_ATTR_U16,
	TRILL_ATTR_BIN,
	__TRILL_ATTR_MAX,
};
#define TRILL_ATTR_MAX (__TRILL_ATTR_MAX-1)

/* GET and set are from user space perspective  example TRILL_CMD_GET_BRIDGE
 * means that the kernel will send this bridge name to userspace
 */
enum {
	TRILL_CMD_UNSPEC,
	TRILL_CMD_SET_NICKS_INFO,
	TRILL_CMD_GET_NICKS_INFO,
	TRILL_CMD_ADD_NICKS_INFO,
	TRILL_CMD_DEL_NICK,
	TRILL_CMD_SET_TREEROOT_ID,
	TRILL_CMD_GET_RBRIDGE,
	TRILL_CMD_SET_RBRIDGE,
	TRILL_CMD_PORT_FLUSH,
	TRILL_CMD_NICK_FLUSH,
	__TRILL_CMD_MAX,
};
#define TRILL_CMD_MAX (__TRILL_CMD_MAX - 1)

int __init rbridge_register_genl(void);
void __exit rbridge_unregister_genl(void);

/* used to indicate that message is provided by kernel to user space */
#define KERNL_RESPONSE_INTERFACE -1

#endif /* RBR_NETLINK_H_ */
