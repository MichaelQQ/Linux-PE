/* This is a module which is used for redirecting packets into MPLS land. */

/* (C) 1999-2007 James R. Leu <jleu@mindspring.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/route.h>
#include <net/mpls.h>
#include <net/checksum.h>

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_mpls.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("James R. Leu <jle@mindspring.com>");
MODULE_DESCRIPTION("ip[6]tables mpls module");
MODULE_ALIAS("ipt_mpls");
MODULE_ALIAS("ip6t_mpls");

static unsigned int
target(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_mpls_target_info *mplsinfo = par->targinfo;
	struct mpls_nhlfe *nhlfe = mplsinfo->nhlfe;

	if (mpls_set_nexthop2(nhlfe, skb_dst(skb))) {
		return NF_DROP;
	}
	return XT_CONTINUE;
}

static int
checkentry(const struct xt_tgchk_param *par)
{
	struct xt_mpls_target_info *mplsinfo = par->targinfo;
	mplsinfo->nhlfe = mpls_get_nhlfe(mplsinfo->key);
	if (!mplsinfo->nhlfe) {
		printk(KERN_WARNING "mpls: unable to find NHLFE with key %x\n",
			mplsinfo->key);
		return -EINVAL;
	}
	return 0;
}

static void
destroy(const struct xt_tgdtor_param *par)
{
	struct xt_mpls_target_info *mplsinfo = par->targinfo;
	if (mplsinfo->nhlfe)
		mpls_nhlfe_release(mplsinfo->nhlfe);
}

static struct xt_target xt_mpls_target[] = {
	{
		.name		= "mpls",
		.family		= AF_INET,
		.revision	= 0,
		.checkentry	= checkentry,
		.target		= target,
		.destroy	= destroy,
		.targetsize	= sizeof(struct xt_mpls_target_info),
		.table		= "mangle",
		.me		= THIS_MODULE,
	},
	{
		.name		= "mpls",
		.family		= AF_INET6,
		.revision	= 0,
		.checkentry	= checkentry,
		.target		= target,
		.destroy	= destroy,
		.targetsize	= sizeof(struct xt_mpls_target_info),
		.table		= "mangle",
		.me		= THIS_MODULE,
	},
};

static int __init xt_mpls_init(void)
{
	return xt_register_targets(xt_mpls_target, ARRAY_SIZE(xt_mpls_target));
}

static void __exit xt_mpls_fini(void)
{
	xt_unregister_targets(xt_mpls_target, ARRAY_SIZE(xt_mpls_target));
}

module_init(xt_mpls_init);
module_exit(xt_mpls_fini);
