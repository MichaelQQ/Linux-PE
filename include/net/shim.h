/*
 *	Network shim interface for protocols that live below L3 but above L2
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 *	Authors:	James R. Leu <jleu@mindspring.com>
 */
#ifndef _NET_SHIM_H
#define _NET_SHIM_H

#include <net/dst.h>
#include <linux/list.h>
#include <linux/shim.h>

struct shim_blk;

struct shim {
	atomic_t		refcnt;
	struct list_head	list;
	int			(*build)(struct shim_blk *, struct dst_entry *);
	char			name[SHIMNAMSIZ + 1];
};

struct shim_blk {
	struct shim *shim;
	short datalen;
	char data[0];
};

extern void shim_proto_add(struct shim *spec);
extern int shim_proto_remove(struct shim *spec);
extern struct shim *shim_proto_find_by_name(const char* name);
extern struct shim_blk *shim_build_blk(struct rtshim* data);
extern  void shim_destroy_blk(struct shim_blk* sblk);
extern int shim_blk_cmp(struct shim_blk* a, struct shim_blk* b);
extern int shim_cfg_blk_cmp(struct rtshim* data, struct shim_blk* sblk);
extern void shim_unbuild_blk(struct rtshim* data, struct shim_blk* sblk);

#define shim_proto_release(V)	atomic_dec((&V->refcnt));
#define shim_proto_hold(V)	atomic_inc((&V->refcnt));

#endif
