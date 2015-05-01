/* This is a module which is used for setting up a SKB to use a mpls. */
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/route.h>
#include <net/checksum.h>
#include <net/mpls.h>

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("James R. Leu <jle@mindspring.com>");
MODULE_DESCRIPTION("iptables mpls module");

static unsigned int
mpls_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct mpls_netfilter_target_info *mpls_info = par->targinfo;
	struct mpls_nhlfe *nhlfe = mpls_info->nhlfe;

	if (mpls_set_nexthop2(nhlfe, skb_dst(skb))) {
		return NF_DROP;
	}
	return XT_CONTINUE;
}

static int
mpls_tg_check(const struct xt_tgchk_param *par)
{
	struct mpls_netfilter_target_info *mpls_info = par->targinfo;

	mpls_info->nhlfe = mpls_get_nhlfe(mpls_info->key);
	if (!mpls_info->nhlfe) {
		printk(KERN_WARNING "mpls: unable to find NHLFE with key %x\n",
			mpls_info->key);
		return 0;
	}

	return 1;
}

static void destroy(void *targinfo, unsigned int targinfosize)
{
	struct mpls_netfilter_target_info *mpls_info = targinfo;
	struct mpls_nhlfe *nhlfe = mpls_info->nhlfe;

	if (nhlfe) {
		mpls_nhlfe_release(nhlfe);
		mpls_info->nhlfe = NULL;
		rt_cache_flush(0);
	}
}

static struct xt_target ipt_mpls_reg = {
	.name           = "mpls",
	.target         = mpls_tg,
	.targetsize	= sizeof(struct mpls_netfilter_target_info),
	.destroy	= destroy,
	.checkentry     = mpls_tg_check,
	.me             = THIS_MODULE,
};

static int __init init(void)
{
	if (xt_register_target(&ipt_mpls_reg))
		return -EINVAL;

	return 0;
}

static void __exit fini(void)
{
	xt_unregister_target(&ipt_mpls_reg);
}

module_init(init);
module_exit(fini);

