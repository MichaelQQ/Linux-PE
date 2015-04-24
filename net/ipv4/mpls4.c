/* mpls4.c: IPv4 MPLS protocol driver.
 *
 * Copyright (C) 2003 David S. Miller (davem@redhat.com)
 *
 * Changes:
 *	JLEU: 	Add ICMP handling
 *		Add nexthop printing
 *		Change nexthop resolve signature
 *	JLEU:	Added mpls4_cache_flush()
 *	JLEU:	un/register reserved labels in fini/init
 *	JLEU:	removed sysfs print routin
 */

#include <linux/module.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/init.h>
#include <net/dsfield.h>
#include <net/neighbour.h>
#include <net/route.h>
#include <net/ip.h>
#include <net/mpls.h>
#include <net/icmp.h>
#include <net/checksum.h>
#include <net/arp.h>

MODULE_LICENSE("GPL");

static void mpls4_cache_flush(struct net *net)
{
	rt_cache_flush(net);
}

static void mpls4_set_ttl(struct sk_buff *skb, int ttl)
{
	ip_hdr(skb)->ttl = ttl;
	ip_send_check(ip_hdr(skb));
}

static int mpls4_get_ttl(struct sk_buff *skb)
{
	return ip_hdr(skb)->ttl;
}

static void mpls4_change_dsfield(struct sk_buff *skb, int ds)
{
	ipv4_change_dsfield(ip_hdr(skb), 0x3, ds << 2);
}

static int mpls4_get_dsfield(struct sk_buff *skb)
{
	return ipv4_get_dsfield(ip_hdr(skb)) >> 2;
}

struct mpls_icmp_common {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8    res1:4,
		version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8    version:4,
		res1:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
	__u8	res2;
	__u16	check;
};

struct mpls_icmp_object {
	__u16	length;
	__u8	class;
	__u8	type;
};

/* we can probably used a modified ip_append_data to build this */
static struct sk_buff*
mpls4_build_icmp(struct sk_buff *skb, int type, unsigned int icmp_data,
	int mpls)
{
	unsigned char buf[576];

	struct icmphdr *icmph;
	struct sk_buff *nskb;
	unsigned char *data;
	struct rtable *rt;
	struct iphdr *iph;

	unsigned int icmp_start = 0;
	unsigned int len = 0;
	unsigned int real;
	unsigned int max;
	unsigned int height;
	int pull;

	/* find the distance to the bottom of the MPLS stack */
	pull = mpls_find_payload(skb);
	if (pull < 0)
		goto error_0;

	if (!skb_pull(skb, pull))
		goto error_0;

	height = skb->data - MPLSCB(skb)->top_of_stack;

	/* now where at the payload, for now we're
	 * assuming this is IPv4
	 */
	skb_reset_network_header(skb);

	/* buid a new skb, that will be big enough to hold
	 * a maximum of 576 bytes (RFC792)
	 */
	if ((skb->len + skb_tailroom(skb)) < 576) {
		nskb = skb_copy_expand(skb, skb_headroom(skb),
			(576 + 16) - skb->len, GFP_ATOMIC);
	} else {
		nskb = skb_copy(skb, GFP_ATOMIC);
	}

	if (!nskb)
		goto error_0;

	/* I don't handle IP options */
	if (ip_hdr(nskb)->ihl > 5) {
		printk("Options!!!!\n");
		goto error_1;
	}

	memset(buf, 0, sizeof(buf));

	/* point to the buf, we'll build our ICMP message there
	 * then copy to nskb when we're done
	 */
	iph = (struct iphdr*)&buf[len];
	iph->version = 4;
	iph->ihl = 5;
	iph->tos = ip_hdr(nskb)->tos;
	iph->tot_len = 0;
	iph->id = 0;
	iph->frag_off = 0;
	iph->ttl = sysctl_mpls_default_ttl;
	iph->protocol = IPPROTO_ICMP;
	iph->check = 0;
	iph->saddr = ip_hdr(nskb)->daddr;
	iph->daddr = ip_hdr(nskb)->saddr;
	len += sizeof(struct iphdr);

	icmp_start = len;
 	icmph = (struct icmphdr*)&buf[len];
	icmph->checksum = 0;
	icmph->un.gateway = icmp_data;

	switch (type) {
		case ICMP_TIME_EXCEEDED:
			icmph->type = ICMP_TIME_EXCEEDED;
			icmph->code = ICMP_EXC_TTL;
			break;
		case ICMP_DEST_UNREACH:
			icmph->type = ICMP_DEST_UNREACH;
			icmph->code = ICMP_FRAG_NEEDED;
			break;
		default:
			BUG_ON(1);
			break;
	}
	len += sizeof(struct icmphdr);

 	data = &buf[len];
	if (mpls) {
		max = 128;
	} else {
		max = 576 - len;
	}
	real = (nskb->len > max) ? max : skb->len;
	memcpy(data, nskb->data, real);

	if (!mpls) {
		len += real;
	} else {
		struct mpls_icmp_common *common;
		struct mpls_icmp_object *object;
		unsigned char *mpls_data = NULL;
		unsigned int obj_start = 0;
		unsigned int mpls_start = 0;

		len += 128;

		mpls_start = len;
		common = (struct mpls_icmp_common*)&buf[len];
		common->version = 2;
		common->res1 = 0;
		common->res2 = 0;
		common->check = 0;
		len += sizeof(struct mpls_icmp_common);

		obj_start = len;
		object = (struct mpls_icmp_object*)&buf[len];
		object->length = 0;
		object->class = 1;
		object->type = 1;
		len += sizeof(struct mpls_icmp_object);

		mpls_data = &buf[len];
		memcpy(mpls_data, MPLSCB(skb)->top_of_stack, height);
		len += height;

		object->length = htons(len - obj_start);
		common->check = csum_fold (csum_partial ((char*)common,
			len - mpls_start, 0));
	}

	iph->tot_len = htons(len);
	ip_send_check(iph);
	icmph->checksum = csum_fold (csum_partial ((char*)icmph,
		len - icmp_start, 0));

	nskb->len = len;
	memcpy(nskb->data, buf, nskb->len);
	nskb->tail = nskb->data + nskb->len;

	nskb->ip_summed = CHECKSUM_NONE;
	nskb->csum = 0;

	{
		struct flowi4 fl = {
				.daddr = iph->daddr,
				.saddr = iph->saddr,
				.__fl_common.flowic_tos = RT_TOS(iph->tos),
				.__fl_common.flowic_proto = IPPROTO_ICMP
			};

		if (ip_route_output_key(&init_net, &fl))
			goto error_1;
	}

	if (skb_dst(nskb))
		dst_release(skb_dst(nskb));

	skb_dst_set(nskb, &rt->dst);

	return nskb;

error_1:
	kfree_skb(nskb);
error_0:
	return NULL;
}

/* Policy decision, several options:
 *
 * 1) Silently discard
 * 2) Pops all MPLS headers, use resulting upper-layer
 *    protocol packet to generate ICMP.
 * 3) Walk down MPLS headers to upper-layer header,
 *    generate ICMP using that and then prepend
 *    IDENTICAL MPLS header stack to ICMP packet.
 *
 * Problem with #2 is that there may be no route to
 * upper-level packet source for us to use.  (f.e. we
 * are switching VPN packets that we have no routes to).
 *
 * Option #3 should work even in those cases, because it
 * is more likely that egress of this MPLS path knows how
 * to route such packets back to source.  It should also
 * not be susceptible to loops in MPLS fabric, since one
 * never responds to ICMP with ICMP.  It is deliberate
 * assumption made about upper-layer protocol.
 */
static int mpls4_ttl_expired(struct sk_buff **skb)
{
	struct sk_buff *nskb;

	if ((nskb = mpls4_build_icmp(*skb, ICMP_TIME_EXCEEDED, 0, 1)))
		if (dst_output(nskb))
			kfree_skb(nskb);

	/* make sure the MPLS stack frees the original skb! */
	return NET_RX_DROP;
}

static int mpls4_mtu_exceeded(struct sk_buff **skb, int mtu)
{
	struct sk_buff *nskb;

	if ((nskb = mpls4_build_icmp(*skb, ICMP_DEST_UNREACH, htonl(mtu), 0)))
		if (dst_output(nskb))
			kfree_skb(nskb);

	/* make sure the MPLS stack frees the original skb! */
	return MPLS_RESULT_DROP;
}

static int mpls4_local_deliver(struct sk_buff *skb)
{
	skb->protocol = htons(ETH_P_IP);
	memset(skb->cb, 0, sizeof(skb->cb));
	dst_release(skb_dst(skb));
	skb_dst_set(skb, NULL);
	return ip_rcv(skb, skb->dev, NULL, skb->dev);
}

#if defined(CONFIG_ATM_CLIP) || defined(CONFIG_ATM_CLIP_MODULE)
extern struct neigh_table *clip_tbl_hook;
#endif

static int mpls4_nexthop_resolve(struct neighbour **np, struct sockaddr *sock_addr, struct net_device *dev)
{
	struct sockaddr_in *addr = (struct sockaddr_in *) sock_addr;
	struct neighbour *n;
	u32 nexthop;

	if (addr->sin_family == AF_INET) {
		nexthop = addr->sin_addr.s_addr;
	} else if (!addr->sin_family) {
		nexthop = 0;
	} else {
	        return -EINVAL;
	}

	n = __neigh_lookup_errno(
#if defined(CONFIG_ATM_CLIP) || defined(CONFIG_ATM_CLIP_MODULE)
		dev->type == ARPHRD_ATM ? clip_tbl_hook :
#endif
		&arp_tbl, &nexthop, dev);

	if (IS_ERR(n))
	    return PTR_ERR(n);

	*np = n;
	return 0;
}

static struct mpls_prot_driver mpls4_driver = {
	.name			=	"ipv4",
	.family                 =       AF_INET,
	.ethertype              =       __constant_htons(ETH_P_IP),
	.cache_flush            =       mpls4_cache_flush,
	.set_ttl                =       mpls4_set_ttl,
	.get_ttl                =       mpls4_get_ttl,
	.change_dsfield         =       mpls4_change_dsfield,
	.get_dsfield            =       mpls4_get_dsfield,
	.ttl_expired            =       mpls4_ttl_expired,
	.mtu_exceeded		=	mpls4_mtu_exceeded,
	.local_deliver		=	mpls4_local_deliver,
	.nexthop_resolve        =       mpls4_nexthop_resolve,
	.owner                  =       THIS_MODULE,
};

static int __init mpls4_init(void)
{
	struct mpls_instr_elem instr[2];
	struct mpls_label ml;
	struct mpls_ilm *ilm;
	int result = mpls_proto_add(&mpls4_driver);

	printk("MPLS: IPv4 over MPLS support\n");

	if (result)
		return result;

	ml.ml_type = MPLS_LABEL_GEN;
	ml.u.ml_gen = MPLS_IPV4_EXPLICIT_NULL;

	instr[0].mir_direction = MPLS_IN;
	instr[0].mir_opcode    = MPLS_OP_POP;
	instr[1].mir_direction = MPLS_IN;
	instr[1].mir_opcode    = MPLS_OP_DLV;

	ilm = mpls_ilm_dst_alloc(0, &ml, AF_INET, instr, 2, NULL, 0);
	if (!ilm)
		return -ENOMEM;

	result = mpls_add_reserved_label(MPLS_IPV4_EXPLICIT_NULL, ilm);
	if (result) {
		ilm->u.dst.obsolete = 1;
		dst_free(&ilm->u.dst);
		return result;
	}

	return 0;
}

static void __exit mpls4_fini(void)
{
	struct mpls_ilm *ilm = mpls_del_reserved_label(MPLS_IPV4_EXPLICIT_NULL);
	if (ilm) {
		__mpls_del_in_label(ilm);
	}
	mpls_proto_remove(&mpls4_driver);
}

module_init(mpls4_init);
module_exit(mpls4_fini);
