/* mplsbr.c: ethernet over MPLS protocol driver.
 *
 * Copyright (C) 2005 James R. Leu (jleu@mindspring.com)
 */

#include <linux/module.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <net/neighbour.h>
#include <net/dst.h>
#include <net/mpls.h>

MODULE_LICENSE("GPL");

static void dumb_neigh_solicit(struct neighbour *neigh,struct sk_buff *skb)
{
}

static void dumb_neigh_error(struct neighbour *neigh,struct sk_buff *skb)
{
	kfree_skb(skb);
}

static int dumb_neigh_dev_xmit(struct net *net, struct sk_buff *skb)
{
	struct net_device *dev;
	struct dst_entry *dst = (struct dst_entry*)skb->_skb_refdst;

        dev = __dev_get_by_name(net, skb->dev->name);
        skb->dev = dst->dev;
        skb->ip_summed = CHECKSUM_NONE;
        mpls_re_tx(skb,dev);
        return 0;
}


static struct neigh_ops dumb_neigh_ops = {
	.family =               AF_PACKET,
	.solicit =              dumb_neigh_solicit,
	.error_report =         dumb_neigh_error,
	.output =               dumb_neigh_dev_xmit,
	.connected_output =     dumb_neigh_dev_xmit,
};

static u32 dumb_neigh_hash(const void *pkey, const struct net_device *dev)
{
	return dev->ifindex;
}

static int dumb_neigh_constructor(struct neighbour *neigh)
{
	neigh->ops = &dumb_neigh_ops;
	neigh->output = neigh->ops->output;
	return 0;
}

static struct neigh_table dumb_tbl = {
	.family         = AF_PACKET,
	.entry_size     = sizeof(struct neighbour),
	.key_len        = 4,
	.hash           = dumb_neigh_hash,
	.constructor    = dumb_neigh_constructor,
	.id             = "dumb_neigh",

	/* parameters are copied from ARP ... */
	.parms = {
		.tbl                    = &dumb_tbl,
		.base_reachable_time    = 30 * HZ,
		.retrans_time           = 1 * HZ,
		.gc_staletime           = 60 * HZ,
		.reachable_time         = 30 * HZ,
		.delay_probe_time       = 5 * HZ,
		.queue_len_bytes        = 3,
		.ucast_probes           = 3,
		.mcast_probes           = 3,
		.anycast_delay          = 1 * HZ,
		.proxy_delay            = (8 * HZ) / 10,
		.proxy_qlen             = 64,
		.locktime               = 1 * HZ,
	},
	.gc_interval    = 30 * HZ,
	.gc_thresh1     = 128,
	.gc_thresh2     = 512,
	.gc_thresh3     = 1024,
};

static void mplsbr_cache_flush(struct net *net)
{
}

static void mplsbr_set_ttl(struct sk_buff *skb, int ttl)
{
}

static int mplsbr_get_ttl(struct sk_buff *skb)
{
	return 255;
}

static void mplsbr_change_dsfield(struct sk_buff *skb, int ds)
{
	/* 802.1q? */
}

static int mplsbr_get_dsfield(struct sk_buff *skb)
{
	/* 802.1q? */
	return 0;
}

static int mplsbr_ttl_expired(struct sk_buff **skb)
{
	return NET_RX_DROP;
}

static int mplsbr_mtu_exceeded(struct sk_buff **skb, int mtu)
{
	return MPLS_RESULT_DROP;
}

static int mplsbr_local_deliver(struct sk_buff *skb)
{
	return NET_RX_DROP;
}

static int mplsbr_nexthop_resolve(struct neighbour **np,
	struct sockaddr *sock_addr, struct net_device *dev)
{
	struct neighbour *n;
	u32 index = dev->ifindex;

	n = __neigh_lookup_errno(&dumb_tbl, &index, dev);
	if (IS_ERR(n))
		return PTR_ERR(n);

	*np = n;
	return 0;
}

static struct mpls_prot_driver mplsbr_driver = {
	.name			=	"bridge",
	.family                 =       AF_PACKET,
	.ethertype              =       __constant_htons(ETH_P_ALL),
	.cache_flush            =       mplsbr_cache_flush,
	.set_ttl                =       mplsbr_set_ttl,
	.get_ttl                =       mplsbr_get_ttl,
	.change_dsfield         =       mplsbr_change_dsfield,
	.get_dsfield            =       mplsbr_get_dsfield,
	.ttl_expired            =       mplsbr_ttl_expired,
	.mtu_exceeded		=	mplsbr_mtu_exceeded,
	.local_deliver		=	mplsbr_local_deliver,
	.nexthop_resolve        =       mplsbr_nexthop_resolve,
	.owner                  =       THIS_MODULE,
};

static int __init mplsbr_init(void)
{
	printk("MPLS: Ethernet over MPLS support\n");
	neigh_table_init(&dumb_tbl);
	return mpls_proto_add(&mplsbr_driver);
}

static void __exit mplsbr_fini(void)
{
	mpls_proto_remove(&mplsbr_driver);
}

module_init(mplsbr_init);
module_exit(mplsbr_fini);
