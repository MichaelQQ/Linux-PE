/*****************************************************************************
 * MPLS
 *      An implementation of the MPLS (MultiProtocol Label
 *      Switching Architecture) for Linux.
 *
 * Authors:
 *	  James Leu	<jleu@mindspring.com>
 *	  Ramon Casellas   <casellas@infres.enst.fr>
 *
 *   (c) 1999-2004   James Leu        <jleu@mindspring.com>
 *   (c) 2003-2004   Ramon Casellas   <casellas@infres.enst.fr>
 *
 *	      It implements:
 *	      -the MPLS dst_entry life cycle.
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
 *	IMPORTANT: We manage "mpls_dst" cache objects, which live in 
 *	AF_MPLS, for either ETH_P_MPLS_UC/ETH_P_MPLS_MC. Nevertheless
 *	these mpls_dst objects hold references to neighbours that live
 *	in the AF_INET and/or AF_INET6 neighbour tables.
 *
 *	20040206 - RCAS: Note that the DST parent is the MOI object.
 *
 ****************************************************************************/

#include <generated/autoconf.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <net/mpls.h>
#include <net/arp.h>

/* forward declarations */
static struct dst_entry *mpls_dst_check(struct dst_entry *dst, u32 cookie);
static void		 mpls_dst_destroy(struct dst_entry *dst);
static struct dst_entry *mpls_negative_advice(struct dst_entry *dst);
static void		 mpls_link_failure(struct sk_buff *skb);
static void		 mpls_dst_update_pmtu(struct dst_entry *dst, u32 mtu);
static int		 mpls_dst_gc(struct dst_ops *ops);

struct dst_ops mpls_dst_ops = {
	.family          =  AF_MPLS,
	.protocol        = __constant_htons(ETH_P_MPLS_UC),
	.gc              = mpls_dst_gc,
	.check           = mpls_dst_check,
	.destroy         = mpls_dst_destroy,
	.negative_advice = mpls_negative_advice,
	.link_failure    = mpls_link_failure,
	.update_pmtu     = mpls_dst_update_pmtu,
};


static struct dst_entry *
mpls_dst_check (struct dst_entry *dst, u32 cookie)
{
	MPLS_ENTER;
	dst_release(dst);
	MPLS_EXIT;
	return NULL;
}



/** 
 *	mpls_dst_destroy - cleanup for a MPLS dst_entry
 *	@dst: 'this', object that is being destroyed.
 *
 *	The object ends life here. Perform the necessary
 *	clean up, but do not call dst_free(..) etc. 
 **/
 
static void 
mpls_dst_destroy (struct dst_entry *dst)
{
	MPLS_ENTER;
	MPLS_EXIT;
}



static struct dst_entry *
mpls_negative_advice (struct dst_entry *dst)
{
	struct mpls_dst *md = (struct mpls_dst*)dst;
	struct dst_entry *ret = dst;
										
	MPLS_ENTER;
	if (md) {
		if (dst->obsolete || md->u.dst.expires) {
			dst_release((struct dst_entry*)md);
			ret = NULL;
		}
	}
	MPLS_EXIT;
	return ret;
}

static void 
mpls_link_failure (struct sk_buff *skb)
{
	struct mpls_dst *md;

	MPLS_ENTER;
//	icmp_send(skb, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, 0);

	if ((md = (struct mpls_dst *)skb_dst(skb)));
		dst_set_expires(&md->u.dst, 0);
	MPLS_EXIT;
}

int mpls_dst_mtu_expires	= 10 * 60 * HZ;
int mpls_dst_min_pmtu		= 512 + 20 + 20 + 4;

static void 
mpls_dst_update_pmtu (struct dst_entry *dst, u32 mtu)
{
	MPLS_ENTER;
	if (dst->_metrics > mtu && mtu >= 68 &&
	    !(dst_metric_locked (dst, RTAX_MTU)) ) {
		if (mtu < mpls_dst_min_pmtu) {
			mtu = mpls_dst_min_pmtu;
			dst->_metrics |= (1 << RTAX_MTU);
		}
		dst->_metrics = mtu;
		dst_set_expires (dst, mpls_dst_mtu_expires);
	}
	MPLS_EXIT;
}


/**
 *	mpls_dst_gc - MPLS destination cache GC policies.
 *
 *	Actually a NOOP. Return nonzero to veto allocation of a new DST entry.
 **/
static int 
mpls_dst_gc (struct dst_ops *ops)
{
	MPLS_ENTER;
	MPLS_EXIT;
	return 0;
}




/**
 *	mpls_dst_alloc - construct a mpls_dst entry.
 *	@dev: output device.
 *	@nh: address of the next hop (IPv4 or IPv6)
 *
 *	Allocate a new mpls_dst cache object (which basically adds a next hop
 *	attribute to base dst) using dst_alloc () and the dst_ops above. Lookup
 *	(or set up) a neighbour in the AF_INET/AF_INET6 families and hold it.
 *	The hh_type when building the neighbour will be set to ETH_P_MPLS_UC
 *	Called when building the SET opcode, the returned object will be 
 *	stored as the opcode data. Process context only.
 **/
 
struct mpls_dst* 
mpls_dst_alloc ( struct net_device *dev, struct sockaddr *nh)
{
	struct mpls_dst		*md = NULL;
	struct mpls_prot_driver *prot;
	struct mpls_interface	*mif;

	MPLS_ENTER;
	BUG_ON(!nh);
	BUG_ON(!dev);
	mif = mpls_get_if_info(dev->ifindex);
	MPLS_ASSERT(mif);

	if (!nh->sa_family) {
		memset(nh, 0, sizeof(struct sockaddr));
		nh->sa_family = AF_INET;
	}
	prot = mpls_proto_find_by_family(nh->sa_family);
	if (unlikely(!prot))
		goto mpls_dst_alloc_2;

	// Allocate a MPLS dst entry 
	md = dst_alloc (&mpls_dst_ops, dev, 0, DST_OBSOLETE_FORCE_CHK, 0);
	if (unlikely(!md)) 
		goto mpls_dst_alloc_1;

	// Hold it 
	dst_hold(&md->u.dst);

	dev_hold(dev);
	md->u.dst.dev   = dev;
	md->u.dst.flags = DST_HOST;
	//md->u.dst.hh    = NULL;

	// Set next hop MPLS attr 
	memcpy(&md->md_nh,nh,sizeof(struct sockaddr));

	//n = dst_neigh_lookup(&md->u.dst, nh->sa_data);
	// use the protocol driver to resolve the neighbour 
	//if (prot->nexthop_resolve( &md->u.dst.neighbour, nh, dev))
	//	goto mpls_dst_alloc_0;

	mpls_proto_release(prot);

	MPLS_DEBUG("exit(%p)\n",md);
	return md;

mpls_dst_alloc_0:
	// dst_release releases dev and neighbour 
	dst_release(&md->u.dst);
	dst_free(&md->u.dst);

mpls_dst_alloc_1:
	mpls_proto_release(prot);

mpls_dst_alloc_2:
	MPLS_DEBUG("exit(%p)\n",md);
	return NULL;
}



/**
 *	mpls_dst_release - cleanup and release the DST. 
 *
 *	Call base dst_release and call_rcu.
 *
 *	RCAS: _NOTE_ do not release the neighbour
 *	mdst->u.dst.neighbour. when the dst frmwk calls dst_destroy
 *	it will be released.
 **/

void
mpls_dst_release (struct mpls_dst* mdst)
{
	dst_release (&mdst->u.dst);
	call_rcu (&mdst->u.dst.rcu_head, dst_rcu_free);
}



/** 
 * mpls_dst_init - Create mpls DST entries slab allocator
 *
 **/
 
int __init mpls_dst_init(void)
{
	mpls_dst_ops.kmem_cachep = kmem_cache_create("mpls_dst_cache",
		sizeof(struct mpls_dst), 0, SLAB_HWCACHE_ALIGN, NULL);

	if (!mpls_dst_ops.kmem_cachep) {
		printk(MPLS_ERR "MPLS: failed to alloc mpls_dst_cache\n");
		return -ENOMEM;
	}

	return 0;
}


/** 
 * mpls_dst_exit - Destroy mpls DST entries slab allocator
 *
 **/ 

void __exit mpls_dst_exit(void)
{
	if (mpls_dst_ops.kmem_cachep)
		kmem_cache_destroy(mpls_dst_ops.kmem_cachep);
}
