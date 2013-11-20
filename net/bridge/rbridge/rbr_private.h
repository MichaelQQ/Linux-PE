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

#ifndef _RBR_PRIVATE_H
#define _RBR_PRIVATE_H

#include "../br_private.h"
#include <linux/atomic.h>
#include <linux/if_trill.h>

#define	RBRIDGE_NICKNAME_MIN	0x0000
#define	RBRIDGE_NICKNAME_MAX	0xFFFF
/* Define well-known nicknames */
#define	RBRIDGE_NICKNAME_NONE	RBRIDGE_NICKNAME_MIN
#define	RBRIDGE_NICKNAME_UNUSED	RBRIDGE_NICKNAME_MAX

/* Various well-known Ethernet addresses used by TRILL */
#define	ALL_RBRIDGES		{ 0x01, 0x80, 0xC2, 0x00, 0x02, 0x40 }
#define	ALL_ISIS_RBRIDGES	{ 0x01, 0x80, 0xC2, 0x00, 0x02, 0x01 }
#define	ALL_ESADI_RBRIDGES	{ 0x01, 0x80, 0xC2, 0x00, 0x02, 0x02 }

#define	TRILL_PROTOCOL_VERS 0	/* th_version */
#define	TRILL_DEFAULT_HOPS 21	/* th_hopcount */
#define VALID_NICK(n)	((n) != RBRIDGE_NICKNAME_NONE && \
			(n) != RBRIDGE_NICKNAME_UNUSED)

struct rbr_nickinfo {
	/* Nickname of the RBridge */
	uint16_t	nick;
	/* Next-hop SNPA address to reach this RBridge */
	u8		adjsnpa[ETH_ALEN];
	/* Link on our system to use to reach next-hop */
	uint32_t	linkid;
	/* Num of *our* adjacencies on a tree rooted at this RBridge */
	uint16_t	adjcount;
	/* Num of distribution tree root nicks chosen by this RBridge */
	uint16_t	dtrootcount;
	/*
	 * Variable size bytes to store adjacency nicks, distribution
	 * tree roots. Adjacency nicks and
	 * distribution tree roots are 16-bit fields.
	 */
};

struct rbr_node {
	struct rbr_nickinfo	*rbr_ni;
	atomic_t		refs; /* reference count */
};

struct rbr {
	spinlock_t		lock;
	uint16_t		nick; /* our nickname */
	uint16_t		treeroot; /* tree root nickname */
	struct rbr_node		*rbr_nodes[RBRIDGE_NICKNAME_MAX];
	uint			rbr_nodecount;
	struct net_bridge	*br;
};

static inline void rbr_node_free(struct rbr_node *rbr_node)
{
	if (rbr_node != NULL) {
		if (rbr_node->rbr_ni != NULL)
		kfree(rbr_node->rbr_ni);
		kfree(rbr_node);
	}
}

static inline void rbr_node_get(struct rbr_node *rbr_node)
{
	if (rbr_node!=NULL)
		atomic_inc(&rbr_node->refs);
}

static inline void rbr_node_put (struct rbr_node *rbr_node)
{
	if (rbr_node) {
		if (likely(atomic_dec_and_test(&rbr_node->refs)))
			rbr_node_free(rbr_node);
	}
}

extern int set_treeroot(struct rbr *rbr, uint16_t treeroot);
extern struct rbr_node *rbr_find_node(struct rbr *rbr, __u16 nickname);

/* Access the adjacency nick list at the end of rbr_nickinfo */
#define	RBR_NI_ADJNICKSPTR(v) ((uint16_t *)((struct rbr_nickinfo *)(v) + 1))
#define	RBR_NI_ADJNICK(v, n) (RBR_NI_ADJNICKSPTR(v)[(n)])

/* Access the DT root nick list in rbr_nickinfo after adjacency nicks */
#define	RBR_NI_DTROOTNICKSPTR(v) (RBR_NI_ADJNICKSPTR(v)+(v)->adjcount)
#define	RBR_NI_DTROOTNICK(v, n) (RBR_NI_DTROOTNICKSPTR(v)[(n)])

#define	RBR_NI_TOTALSIZE(v) (\
		(sizeof (struct rbr_nickinfo)) + \
		(sizeof (uint16_t) * (v)->adjcount) + \
		(sizeof (uint16_t) * (v)->dtrootcount)\
		)

#endif /* !_RBR_PRIVATE_H */
