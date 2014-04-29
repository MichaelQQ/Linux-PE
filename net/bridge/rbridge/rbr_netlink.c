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

#include <net/genetlink.h>
#include <net/netlink.h>
#include <linux/if_trill.h>
#include <linux/socket.h>
#include "rbr_netlink.h"

static struct nla_policy attrs_policy [TRILL_ATTR_MAX + 1] = {
	[TRILL_ATTR_U16] = {.type = NLA_U16},
	[TRILL_ATTR_BIN] = {.type = NLA_UNSPEC},
};

static struct genl_family trill_genl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = sizeof(struct trill_nl_header),
	.name = TRILL_NL_FAMILY,
	.version = TRILL_NL_VERSION,
	.maxattr = TRILL_ATTR_MAX
};

static const struct genl_multicast_group trill_mcgrps[] = {
	{ .name = TRILL_MCAST_NAME, },
};

int create_node(struct net_bridge_port *p, struct rbr *rbr,
		struct rbr_nickinfo *rbr_ni_partial, struct genl_info *info)
{
	size_t size = 0;
	size_t old_size = 0;
	struct rbr_node* old;
	struct rbr_nickinfo *rbr_ni;

	if (rbr_ni_partial == NULL)
		return -EINVAL;

	size = RBR_NI_TOTALSIZE(rbr_ni_partial);
	if (size > PAGE_SIZE-sizeof(struct trill_nl_header)) {
		pr_warn_ratelimited("create_node: size > (PAGE_SIZE-nickinfo_offset)\n");
		return -EINVAL;
	}
	rbr_ni = kzalloc(size, GFP_KERNEL);
	if (!rbr_ni)
		return -ENOMEM;
	old = rbr->rbr_nodes[rbr_ni_partial->nick];
	nla_memcpy(rbr_ni, info->attrs[TRILL_ATTR_BIN], size);
	if (old)
		old_size = RBR_NI_TOTALSIZE(old->rbr_ni);
	/* replace old node by a new one only if nickname information have changed */
	if (old == NULL || old_size != size ||
	    memcmp(old->rbr_ni, rbr_ni, size)) {
		struct rbr_node *new;

		new = kzalloc(sizeof(*old), GFP_KERNEL);
		if (!new) {
			kfree(rbr_ni);
			return -ENOMEM;
		}
		atomic_set(&new->refs, 1);
		new->rbr_ni = rbr_ni;
		/* avoid deleting node while it is been used for routing */
		rcu_assign_pointer(rbr->rbr_nodes[rbr_ni->nick], new);
		if (old)
			rbr_node_put(old);
	} else {
		kfree(rbr_ni);
	}

	return 0;
}

static int trill_cmd_set_nicks_info(struct sk_buff *skb, struct genl_info *info)
{
	struct trill_nl_header *trnlhdr;
	struct rbr_nickinfo rbr_ni;
	struct net_device *source_port = NULL;
	struct net *net = sock_net(skb->sk);
	struct net_bridge_port *p = NULL;
	int err = -EINVAL;

	nla_memcpy(&rbr_ni, info->attrs[TRILL_ATTR_BIN], sizeof(rbr_ni));
	if (!VALID_NICK(rbr_ni.nick))
		goto fail;

	trnlhdr = info->userhdr;
	if (trnlhdr->ifindex)
		source_port = __dev_get_by_index(net, trnlhdr->ifindex);

	if (!source_port)
		goto fail;

	p = br_port_get_rcu(source_port);
	if (!p || !(p->br) || !(p->br->rbr))
		goto fail;

	err = create_node(p, p->br->rbr, &rbr_ni, info);
	if (err)
		goto fail;

	return 0;

fail:
	printk(KERN_WARNING "trill_cmd_set_nicks_info FAILED\n");
	return err;
}

static int trill_cmd_get_nicks_info(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg;
	struct nlattr *attr;
	struct rbr_nickinfo rbr_ni;
	void *data;
	struct trill_nl_header *trnlhdr;
	struct net_device *source_port = NULL;
	struct net *net = sock_net(skb->sk);
	struct net_bridge_port *p = NULL;
	struct rbr_node *rbr_node;
	int err = -EINVAL;

	nla_memcpy(&rbr_ni, info->attrs[TRILL_ATTR_BIN], sizeof(rbr_ni));
	trnlhdr = info->userhdr;
	if (trnlhdr->ifindex)
		source_port = __dev_get_by_index(net, trnlhdr->ifindex);

	if (!source_port)
		goto fail;

	p = br_port_get_rcu(source_port);
	if (!p || !(p->br) || !(p->br->rbr))
		goto fail;

	rbr_node = rbr_find_node(p->br->rbr, rbr_ni.nick);
	if (!rbr_node)
		goto fail;

	err = -ENOMEM;
	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		goto fail_put;

	trnlhdr = genlmsg_put(msg, info->snd_portid, info->snd_seq,
			      &trill_genl_family, sizeof(*trnlhdr),
			      TRILL_CMD_GET_NICKS_INFO);
	if (!trnlhdr)
		goto fail_free;

	attr = nla_reserve(msg, TRILL_ATTR_BIN,
			   RBR_NI_TOTALSIZE(rbr_node->rbr_ni));
	if (!attr)
		goto fail_free;

	data = nla_data(attr);
	trnlhdr->ifindex = KERNL_RESPONSE_INTERFACE;
	memcpy(data, rbr_node->rbr_ni, RBR_NI_TOTALSIZE(rbr_node->rbr_ni));
	genlmsg_end(msg, trnlhdr);
	rbr_node_put(rbr_node);

	err = genlmsg_reply(msg, info);
	if (err)
		goto fail_put;

	return 0;

fail_free:
	nlmsg_free(msg);
fail_put:
	rbr_node_put(rbr_node);
fail:
	printk(KERN_WARNING "trill_cmd_get_nicks_info FAILED\n");
	return err;
}

static int trill_cmd_add_nicks_info(struct sk_buff *skb, struct genl_info *info)
{
	/* TODO */
	return 0;
}

static int trill_cmd_set_treeroot_id(struct sk_buff *skb,
				     struct genl_info *info)
{
	int err = -EINVAL;
	u16 nickname;
	struct trill_nl_header *trnlhdr;
	struct net_device *source_port = NULL;
	struct net *net = sock_net(skb->sk);
	struct net_bridge_port *p = NULL;

	nickname = nla_get_u16(info->attrs[TRILL_ATTR_U16]);
	trnlhdr = info->userhdr;
	if (trnlhdr->ifindex)
		source_port = __dev_get_by_index(net, trnlhdr->ifindex);

	if (!source_port)
		goto fail;

	p = br_port_get_rcu(source_port);
	if (!p || !(p->br) || !(p->br->rbr))
		goto fail;

	err = set_treeroot(p->br->rbr, htons(nickname));
	if (err)
		goto fail;

	return 0;

fail:
	printk(KERN_WARNING "trill_cmd_set_treeroot_id FAILED\n");
	return err;
}

/* trill_cmd_get_rbridge when started daemon inquire for already
 * existant nickname
 * bridge with TRILL capability may already have a nickname
 * is daemon have crashed
 */
static int trill_cmd_get_rbridge(struct sk_buff *skb, struct genl_info *info)
{
	struct trill_nl_header *trnlhdr;
	struct sk_buff *msg;
	struct net_bridge_port *p;
	struct net_device *source_port = NULL;
	struct net *net = sock_net(skb->sk);
	u16 nickname;
	int err = -EINVAL;

	trnlhdr = info->userhdr;
	if (trnlhdr->ifindex)
		source_port = __dev_get_by_index(net, trnlhdr->ifindex);

	if (!source_port)
		goto fail;

	p = br_port_get_rcu(source_port);
	if (!p || !(p->br))
		goto fail;

	if (p->br->rbr)
		nickname = ntohs(p->br->rbr->nick);
	else
		nickname = RBRIDGE_NICKNAME_NONE;

	err = -ENOMEM;
	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		goto fail;

	trnlhdr = genlmsg_put(msg, info->snd_portid, info->snd_seq,
			      &trill_genl_family, sizeof(*trnlhdr),
			      TRILL_CMD_GET_RBRIDGE);
	if (!trnlhdr)
		goto fail_free;

	trnlhdr->ifindex = KERNL_RESPONSE_INTERFACE;
	nla_put_u16(msg, TRILL_ATTR_U16, nickname);
	genlmsg_end(msg, trnlhdr);

	err = genlmsg_reply(msg, info);
	if (err)
		goto fail;

	return 0;

fail_free:
	nlmsg_free(msg);
fail:
	printk(KERN_WARNING "trill_cmd_get_rbridge FAILED\n");
	return err;
}

/* trill_cmd_set_rbridge when started daemon set chosen nickname after
 * discovering the topology and ensuring nickname uniqueness
 */
static int trill_cmd_set_rbridge(struct sk_buff *skb, struct genl_info *info)
{
	struct trill_nl_header *trnlhdr;
	struct net_device *source_port = NULL;
	struct net_bridge_port *p = NULL;
	struct net_bridge *br = NULL;
	struct net *net = sock_net(skb->sk);
	u16 nickname = nla_get_u16(info->attrs[TRILL_ATTR_U16]);

	trnlhdr = info->userhdr;
	if (trnlhdr->ifindex)
		source_port = __dev_get_by_index(net, trnlhdr->ifindex);

	if (!source_port)
		goto fail;

	p = br_port_get_rcu(source_port);
	if (!p || !(p->br))
		goto fail;

	br = p->br;
	if (!br)
		goto fail;

	/* if daemon has started and bridge TRILL capability
	 * is not enabled then start it
	 */
	if (br->trill_enabled == BR_NO_TRILL)
		br_trill_set_enabled(br, 1);

	if (!(br->rbr))
		goto fail;

	spin_lock_bh(&br->lock);
	br->rbr->nick = htons(nickname);
	spin_unlock_bh(&br->lock);

	return 0;

fail:
	printk(KERN_WARNING "trill_cmd_set_bridge FAILED\n");
	return -EINVAL;
}

static int trill_cmd_port_flush(struct sk_buff *skb, struct genl_info *info)
{
	/* TODO */
	return 0;
}

static int trill_cmd_nick_flush(struct sk_buff *skb, struct genl_info *info)
{
	/* TODO */
	return 0;
}

static struct genl_ops trill_genl_ops[] = {
	{
		.cmd = TRILL_CMD_SET_NICKS_INFO,
		.flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
		.policy = attrs_policy,
		.doit = trill_cmd_set_nicks_info,
	},
	{
		.cmd = TRILL_CMD_GET_NICKS_INFO,
		.flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
		.policy = attrs_policy,
		.doit = trill_cmd_get_nicks_info,
	},
	{
		.cmd = TRILL_CMD_ADD_NICKS_INFO,
		.flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
		.policy = attrs_policy,
		.doit = trill_cmd_add_nicks_info,
	},
	{
		.cmd = TRILL_CMD_SET_TREEROOT_ID,
		.flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
		.policy = attrs_policy,
		.doit = trill_cmd_set_treeroot_id,
	},
	{
		.cmd = TRILL_CMD_GET_RBRIDGE,
		.flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
		.policy = attrs_policy,
		.doit = trill_cmd_get_rbridge,
	},
	{
		.cmd = TRILL_CMD_SET_RBRIDGE,
		.flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
		.policy = attrs_policy,
		.doit = trill_cmd_set_rbridge,
	},
	{
		.cmd = TRILL_CMD_PORT_FLUSH,
		.flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
		.doit = trill_cmd_port_flush,
	},
	{
		.cmd = TRILL_CMD_NICK_FLUSH,
		.flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
		.policy = attrs_policy,
		.doit = trill_cmd_nick_flush,
	},
};

void __exit rbridge_unregister_genl(void)
{
	genl_unregister_family(&trill_genl_family);
}

int __init rbridge_register_genl(void)
{
	int err;

	err = genl_register_family_with_ops_groups(&trill_genl_family, trill_genl_ops, trill_mcgrps);
	if (err)
		goto fail_genl_register_family;

	return 0;

fail_genl_register_family:

	return err;
}
