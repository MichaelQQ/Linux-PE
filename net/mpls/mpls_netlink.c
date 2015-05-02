/*****************************************************************************
 * MPLS
 *      An implementation of the MPLS (MultiProtocol Label
 *      Switching) Architecture for Linux.
 *
 *      NetLink Interface for MPLS subsystem
 *
 * Authors:
 *	  Ramon Casellas   <casellas@infres.enst.fr>
 *
 *   (c) 1999-2005   James Leu	<jleu@mindspring.com>
 *   (c) 2003-2004   Ramon Casellas   <casellas@infres.enst.fr>
 *
 *	20051116 - jleu - convert to genetlink
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
 *****************************************************************************/

#include <generated/autoconf.h>
#include <linux/netdevice.h>
#include <net/arp.h>
#include <net/sock.h>
#include <net/mpls.h>
#include <linux/netlink.h>
#include <net/genetlink.h>
#include <linux/gen_stats.h>
#include <net/net_namespace.h>

extern struct list_head mpls_ilm_list;
extern struct list_head mpls_nhlfe_list;

static struct genl_family genl_mpls = {
	.id = PF_MPLS,
	.name = "nlmpls",
	.hdrsize = 0,
	.version = 0x1,
	.maxattr = MPLS_ATTR_MAX,
};

static const struct genl_multicast_group mpls_gnl_mcgrps[] = {
        { .name = "msg", },
};


/* ILM netlink support */

static int mpls_fill_ilm(struct sk_buff *skb, struct mpls_ilm *ilm,
	 u32 pid, u32 seq, int flag, int event)
{
	struct mpls_in_label_req mil;
	struct gnet_stats_basic stats;
	struct mpls_instr_req *instr;
	void *hdr;

	MPLS_ENTER;

	hdr = genlmsg_put(skb, pid, seq, &genl_mpls, flag, event);

	instr = kmalloc(sizeof(*instr), GFP_KERNEL);
	if (unlikely(!instr))
		goto nla_put_failure;

	mil.mil_proto = ilm->ilm_proto->family;
	memcpy(&mil.mil_label, &ilm->ilm_label, sizeof (struct mpls_label));
	mpls_instrs_unbuild(ilm->ilm_instr, instr);
	instr->mir_direction = MPLS_IN;
	memcpy(&stats, &ilm->ilm_stats, sizeof(stats));
	/* need to add drops here some how */

	nla_put(skb, MPLS_ATTR_ILM, sizeof(mil), &mil);
	nla_put(skb, MPLS_ATTR_INSTR, sizeof(*instr), instr);
	nla_put(skb, MPLS_ATTR_STATS, sizeof(stats), &stats);

	kfree(instr);

	MPLS_EXIT;
	return genlmsg_end(skb, hdr);

nla_put_failure:
	if (instr)
		kfree(instr);
	genlmsg_cancel(skb, hdr);
	MPLS_DEBUG("Exit: -1\n");
	return -ENOMEM;
}

void mpls_ilm_event(int event, struct mpls_ilm *ilm)
{
	struct sk_buff *skb;
	int err;

	MPLS_ENTER;

	skb = nlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (skb == NULL) {
		MPLS_DEBUG("Exit: EINVAL\n");
		return;
	}

	err = mpls_fill_ilm(skb, ilm, 0, 0, 0, event);
	if (err < 0) {
		nlmsg_free(skb);
		MPLS_DEBUG("Exit: EINVAL\n");
		return;
	}
	genlmsg_multicast(&genl_mpls, skb, 0, 0, GFP_KERNEL);
	MPLS_EXIT;
}

static int genl_mpls_ilm_new(struct sk_buff *skb, struct genl_info *info)
{
	struct mpls_in_label_req *mil;
	struct mpls_instr_req *instr = NULL;
	int retval = -EINVAL;

	MPLS_ENTER;

	if (!info->attrs[MPLS_ATTR_ILM])
		return -EINVAL;

	if (info->attrs[MPLS_ATTR_INSTR]) {
		instr = nla_data(info->attrs[MPLS_ATTR_INSTR]);
	}

	mil = nla_data(info->attrs[MPLS_ATTR_ILM]);

	if (info->nlhdr->nlmsg_flags&NLM_F_CREATE)
		retval = mpls_add_in_label(mil);
	else
		retval = 0;

	if ((!retval) && instr &&
		mil->mil_change_flag & MPLS_CHANGE_INSTR) {
		memcpy(&instr->mir_label, &mil->mil_label,
			sizeof(struct mpls_label));
		retval = mpls_set_in_label_instrs(instr);

		/* JLEU: should revert to old instr on failure */
		if (retval)
			mpls_del_in_label(mil);
	}

	if ((!retval) && mil->mil_change_flag & MPLS_CHANGE_PROTO)
		retval = mpls_set_in_label_proto(mil);

	MPLS_DEBUG("Exit: %d\n", retval);
	return retval;
}

static int genl_mpls_ilm_del(struct sk_buff *skb, struct genl_info *info)
{
	struct mpls_in_label_req *mil;
	int retval = -EINVAL;

	MPLS_ENTER;

	mil = nla_data(info->attrs[MPLS_ATTR_ILM]);
	retval = mpls_del_in_label(mil);
	MPLS_DEBUG("Exit: %d\n", retval);
	return retval;
}

static int genl_mpls_ilm_get(struct sk_buff *skb, struct genl_info *info)
{
	struct mpls_in_label_req *mil;
	struct mpls_ilm *ilm;
	int retval = -EINVAL;

	MPLS_ENTER;
	if (!info->attrs[MPLS_ATTR_ILM])
		goto err;

	mil = nla_data(info->attrs[MPLS_ATTR_ILM]);

	if (mil->mil_label.ml_type == MPLS_LABEL_KEY)
		goto err;

	ilm = mpls_get_ilm(mpls_label2key(mil->mil_label.ml_index,
		&mil->mil_label));
	if (!ilm) {
		retval = -ESRCH;
	} else {
		if (mpls_fill_ilm(skb, ilm, info->snd_portid, info->snd_seq,
			0, MPLS_CMD_NEWILM) < 0)
			retval = -EINVAL;

		mpls_ilm_release (ilm);
	}
	retval = genlmsg_unicast(&init_net, skb, info->snd_portid);
err:
	MPLS_DEBUG("Exit: %d\n", retval);
	return retval;
}

static int genl_mpls_ilm_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct mpls_ilm *ilm;
	int entries_to_skip;
	int entry_count;

	entries_to_skip = cb->args[0];
	entry_count = 0;

	MPLS_DEBUG("Enter: entry %d\n", entries_to_skip);
	rcu_read_lock();
	list_for_each_entry_rcu(ilm, &mpls_ilm_list, global) {
		MPLS_DEBUG("Dump: entry %d\n", entry_count);
		if (entry_count >= entries_to_skip) {
			if (mpls_fill_ilm(skb, ilm, NETLINK_CB(cb->skb).portid,
				cb->nlh->nlmsg_seq, NLM_F_MULTI,
				MPLS_CMD_NEWILM) < 0) {
				break;
			}
		}
		entry_count++;
	}
	rcu_read_unlock();
	cb->args[0] = entry_count;

	MPLS_DEBUG("Exit: entry %d\n", entry_count);
	return skb->len;
}

/* NHLFE netlink support */

static int mpls_fill_nhlfe(struct sk_buff *skb, struct mpls_nhlfe *nhlfe,
	u32 pid, u32 seq, int flag, int event)
{
	struct mpls_out_label_req mol;
	struct gnet_stats_basic stats;
	struct mpls_instr_req *instr;
	void *hdr;

	MPLS_ENTER;

	hdr = genlmsg_put(skb, pid, seq, &genl_mpls, flag, event);

	instr = kmalloc(sizeof(*instr), GFP_KERNEL);
	if (unlikely(!instr))
		goto nla_put_failure;

	mol.mol_label.ml_type = MPLS_LABEL_KEY;
	mol.mol_label.u.ml_key = nhlfe->nhlfe_key;
	mol.mol_mtu = nhlfe->nhlfe_mtu;
	mol.mol_propagate_ttl = nhlfe->nhlfe_propagate_ttl;
	mpls_instrs_unbuild(nhlfe->nhlfe_instr, instr);
	instr->mir_direction = MPLS_OUT;
	memcpy(&stats, &nhlfe->nhlfe_stats, sizeof(stats));
	/* need to get drops added here some how */

	nla_put(skb, MPLS_ATTR_NHLFE, sizeof(mol), &mol);
	nla_put(skb, MPLS_ATTR_INSTR, sizeof(*instr), instr);
	nla_put(skb, MPLS_ATTR_STATS, sizeof(stats), &stats);

	kfree(instr);

	MPLS_EXIT;
	return genlmsg_end(skb, hdr);

nla_put_failure:
	if (instr)
		kfree(instr);

	genlmsg_cancel(skb, hdr);
	MPLS_DEBUG("Exit: -1\n");
	return -ENOMEM;
}

void mpls_nhlfe_event(int event, struct mpls_nhlfe *nhlfe, int seq, int pid)
{
	struct sk_buff *skb;
	int err;

	MPLS_ENTER;
	skb = nlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (skb == NULL) {
		MPLS_DEBUG("Exit: EINVAL\n");
		return;
	}

	err = mpls_fill_nhlfe(skb, nhlfe, pid, seq, 0, event);
	if (err < 0) {
		nlmsg_free(skb);
		MPLS_DEBUG("Exit: EINVAL\n");
		return;
	}
	genlmsg_multicast(&genl_mpls, skb, 0, 0, GFP_KERNEL);
	MPLS_EXIT;
}

static int genl_mpls_nhlfe_new(struct sk_buff *skb, struct genl_info *info)
{
	struct mpls_out_label_req *mol;
	struct mpls_instr_req *instr = NULL;
	int retval = -EINVAL;

	MPLS_ENTER;

	if (!info->attrs[MPLS_ATTR_NHLFE])
		return -EINVAL;

	if (info->attrs[MPLS_ATTR_INSTR]) {
		instr = nla_data(info->attrs[MPLS_ATTR_INSTR]);
	}

	mol = nla_data(info->attrs[MPLS_ATTR_NHLFE]);

	if (info->nlhdr->nlmsg_flags&NLM_F_CREATE) {
		if (mol->mol_label.ml_type != MPLS_LABEL_KEY ||
		    mol->mol_label.u.ml_key)
			retval = -EINVAL;
		else {
			retval = mpls_add_out_label(mol, info->snd_seq,
				info->snd_portid);
		}
	} else {
		retval = 0;
	}

	if ((!retval) && instr &&
		mol->mol_change_flag & MPLS_CHANGE_INSTR) {
		memcpy(&instr->mir_label, &mol->mol_label,
			sizeof(struct mpls_label));
		retval = mpls_set_out_label_instrs(instr);
		/* JLEU: should revert to old instr on failure */
	}

	if ((!retval) &&  mol->mol_change_flag & MPLS_CHANGE_MTU)
		retval = mpls_set_out_label_mtu(mol);

	if ((!retval) && mol->mol_change_flag & MPLS_CHANGE_PROP_TTL)
		retval = mpls_set_out_label_propagate_ttl(mol);

	MPLS_DEBUG("Exit: %d\n", retval);
	return retval;
}

static int genl_mpls_nhlfe_del(struct sk_buff *skb, struct genl_info *info)
{
	struct mpls_out_label_req *mol;
	int retval = -EINVAL;

	MPLS_ENTER;

	mol = nla_data(info->attrs[MPLS_ATTR_NHLFE]);
	retval = mpls_del_out_label(mol);
	MPLS_DEBUG("Exit: %d\n", retval);
	return retval;
}

static int genl_mpls_nhlfe_get(struct sk_buff *skb, struct genl_info *info)
{
	struct mpls_out_label_req *mol;
	struct mpls_nhlfe *nhlfe;
	int retval = -EINVAL;

	MPLS_ENTER;
	if (!info->attrs[MPLS_ATTR_NHLFE])
		goto err;

	mol = nla_data(info->attrs[MPLS_ATTR_NHLFE]);

	if (mol->mol_label.ml_type != MPLS_LABEL_KEY)
		goto err;

	nhlfe = mpls_get_nhlfe(mol->mol_label.u.ml_key);
	if (!nhlfe) {
		retval = -ESRCH;
	} else {
		if (mpls_fill_nhlfe(skb, nhlfe, info->snd_portid, info->snd_seq,
			0, MPLS_CMD_NEWNHLFE) < 0)
			retval = -EINVAL;

		mpls_nhlfe_release (nhlfe);
	}
	retval = genlmsg_unicast(&init_net, skb, info->snd_portid);
err:
	MPLS_DEBUG("Exit: %d\n", retval);
	return retval;
}

static int genl_mpls_nhlfe_dump(struct sk_buff *skb,
	struct netlink_callback *cb)
{
	struct mpls_nhlfe *nhlfe;
	int entries_to_skip;
	int entry_count;

	entries_to_skip = cb->args[0];
	entry_count = 0;

	MPLS_DEBUG("Enter: entry %d\n", entries_to_skip);
	rcu_read_lock();
	list_for_each_entry_rcu(nhlfe, &mpls_nhlfe_list, global) {
		MPLS_DEBUG("Dump: entry %d\n", entry_count);
		if (entry_count >= entries_to_skip) {
			if (mpls_fill_nhlfe(skb, nhlfe, NETLINK_CB(cb->skb).portid,
				cb->nlh->nlmsg_seq, NLM_F_MULTI,
				MPLS_CMD_NEWNHLFE) <= 0) {
				break;
			}
		}
		entry_count++;
	}
	rcu_read_unlock();
	cb->args[0] = entry_count;

	MPLS_DEBUG("Exit: entry %d\n", entry_count);
	return skb->len;
}

/* XC netlink support */

static int mpls_fill_xc(struct sk_buff *skb, struct mpls_ilm *ilm,
	struct mpls_nhlfe *nhlfe, u32 pid, u32 seq, int flag, int event)
{
	struct mpls_xconnect_req xc;
	void *hdr;

	hdr = genlmsg_put(skb, pid, seq, &genl_mpls, flag, event);

	memcpy(&xc.mx_in, &ilm->ilm_label, sizeof (struct mpls_label));
	xc.mx_out.ml_type = MPLS_LABEL_KEY;
	xc.mx_out.u.ml_key = nhlfe->nhlfe_key;

	nla_put(skb, MPLS_ATTR_XC, sizeof(xc), &xc);

	MPLS_DEBUG("Exit: length\n");
	return genlmsg_end(skb, hdr);

/*nla_put_failure:
	genlmsg_cancel(skb, hdr);
	MPLS_DEBUG("Exit: -1\n");
	return -ENOMEM;*/
}

void mpls_xc_event(int event, struct mpls_ilm *ilm,
	struct mpls_nhlfe *nhlfe)
{
	struct sk_buff *skb;
	int err;

	MPLS_ENTER;
	skb = nlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (skb == NULL) {
		MPLS_DEBUG("Exit: EINVAL\n");
		return;
	}

	err = mpls_fill_xc(skb, ilm, nhlfe, 0, 0, 0, event);
	if (err < 0) {
		nlmsg_free(skb);
		MPLS_DEBUG("Exit: EINVAL\n");
		return;
	}
	genlmsg_multicast(&genl_mpls, skb, 0, 0, GFP_KERNEL);
	MPLS_EXIT;
}

static int genl_mpls_xc_new(struct sk_buff *skb, struct genl_info *info)
{
	struct mpls_xconnect_req *xc;
	int retval = -EINVAL;

	MPLS_ENTER;

	if (!info->attrs[MPLS_ATTR_XC])
		return -EINVAL;

	xc = nla_data(info->attrs[MPLS_ATTR_XC]);

	if (!(info->nlhdr->nlmsg_flags&NLM_F_CREATE))
		retval = -EINVAL;
	else
		retval = mpls_attach_in2out(xc);
	MPLS_DEBUG("Exit: %d\n", retval);
	return retval;
}

static int genl_mpls_xc_del(struct sk_buff *skb, struct genl_info *info)
{
	struct mpls_xconnect_req *xc;
	int retval = -EINVAL;

	MPLS_ENTER;

	xc = nla_data(info->attrs[MPLS_ATTR_XC]);
	retval = mpls_detach_in2out(xc);
	MPLS_DEBUG("Exit: %d\n", retval);
	return retval;
}

static int genl_mpls_xc_get(struct sk_buff *skb, struct genl_info *info)
{
	struct mpls_xconnect_req *xc;
	struct mpls_ilm *ilm;
	struct mpls_nhlfe *nhlfe;
	struct mpls_instr *mi;
	int retval = -EINVAL;

	MPLS_ENTER;
	if (!info->attrs[MPLS_ATTR_XC])
		goto err;

	xc = nla_data(info->attrs[MPLS_ATTR_XC]);

	if (xc->mx_in.ml_type == MPLS_LABEL_KEY) {
		retval = -EINVAL;
		goto err;
	}

	ilm = mpls_get_ilm(mpls_label2key(xc->mx_in.ml_index,
		&xc->mx_in));
	if (!ilm) {
		retval = -ESRCH;
	} else {
		/* Fetch the last instr, make sure it is FWD */
		for (mi = ilm->ilm_instr;
		     mi->mi_next;mi = mi->mi_next); /* noop */

		if (!mi || mi->mi_opcode != MPLS_OP_FWD) {
			retval = -ENXIO;
		} else {
			nhlfe = mi->mi_data;

			if (mpls_fill_xc(skb, ilm, nhlfe, info->snd_portid,
				info->snd_seq, 0, MPLS_CMD_NEWXC) < 0)
				retval = -EINVAL;
		}
		mpls_ilm_release (ilm);
	}
	retval = genlmsg_unicast(&init_net, skb, info->snd_portid);
err:
	MPLS_DEBUG("Exit: %d\n", retval);
	return retval;
}

static int genl_mpls_xc_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct mpls_ilm *ilm;
	struct mpls_nhlfe *nhlfe;
	struct mpls_instr *mi;
	int entries_to_skip;
	int entry_count;

	entries_to_skip = cb->args[0];
	entry_count = 0;

	MPLS_DEBUG("Enter: entry %d\n", entries_to_skip);
	rcu_read_lock();
	list_for_each_entry_rcu(ilm, &mpls_ilm_list, global) {
		MPLS_DEBUG("Dump: entry %d\n", entry_count);
		if (entry_count >= entries_to_skip) {
			/* Fetch the last instr, make sure it is FWD */
			for (mi = ilm->ilm_instr;
			     mi->mi_next;mi = mi->mi_next); /* noop */

			if (!mi || mi->mi_opcode != MPLS_OP_FWD)
				continue;

			nhlfe = mi->mi_data;

			if (mpls_fill_xc(skb, ilm, nhlfe,
				NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq,
				NLM_F_MULTI, MPLS_CMD_NEWXC) < 0) {
				break;
			}
		}
		entry_count++;
	}
	rcu_read_unlock();
	cb->args[0] = entry_count;

	MPLS_DEBUG("Exit: entry %d\n", entry_count);
	return skb->len;
}

/* LABELSPACE netlink support */

static int mpls_fill_labelspace(struct sk_buff *skb, struct net_device *dev,
	    u32 pid, u32 seq, int flag, int event)
{
	struct mpls_labelspace_req ls;
	void *hdr;

	hdr = genlmsg_put(skb, pid, seq, &genl_mpls, flag, event);

	ls.mls_ifindex = dev->ifindex;
	ls.mls_labelspace = mpls_get_labelspace_by_index(dev->ifindex);

	nla_put(skb, MPLS_ATTR_LABELSPACE, sizeof(ls), &ls);

	MPLS_DEBUG("Exit: length\n");
	return genlmsg_end(skb, hdr);

/*nla_put_failure:
	genlmsg_cancel(skb, hdr);
	MPLS_DEBUG("Exit: -1\n");
	return -ENOMEM;*/
}

void mpls_labelspace_event(int event, struct net_device *dev)
{
	struct sk_buff *skb;
	int err;

	MPLS_ENTER;
	skb = nlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (skb == NULL) {
		MPLS_DEBUG("Exit: EINVAL\n");
		return;
	}

	err = mpls_fill_labelspace(skb, dev, 0, 0, 0, event);
	if (err < 0) {
		nlmsg_free(skb);
		MPLS_DEBUG("Exit: EINVAL\n");
		return;
	}
	genlmsg_multicast(&genl_mpls, skb, 0, 0, GFP_KERNEL);
	MPLS_EXIT;
}

static int genl_mpls_labelspace_set(struct sk_buff *skb, struct genl_info *info)
{
	struct mpls_labelspace_req *ls;
	int retval = -EINVAL;

	MPLS_ENTER;
	ls = nla_data(info->attrs[MPLS_ATTR_LABELSPACE]);
	retval = mpls_set_labelspace(ls);
	MPLS_DEBUG("Exit: %d\n", retval);
	return retval;
}

static int genl_mpls_labelspace_get(struct sk_buff *skb, struct genl_info *info)
{
	struct mpls_labelspace_req *ls;
	struct net_device *dev;
	int retval = -EINVAL;

	MPLS_ENTER;
	if (!info->attrs[MPLS_ATTR_LABELSPACE])
		goto err;

	ls = nla_data(info->attrs[MPLS_ATTR_LABELSPACE]);
	dev = dev_get_by_index(&init_net, ls->mls_ifindex);
	if (!dev) {
		retval = -ESRCH;
	} else {
		if (mpls_fill_labelspace(skb, dev, info->snd_portid,
			info->snd_seq, 0, MPLS_CMD_SETLABELSPACE) < 0)
			retval = -EINVAL;
		dev_put (dev);
	}
	retval = genlmsg_unicast(&init_net, skb, info->snd_portid);
err:
	MPLS_DEBUG("Exit: %d\n", retval);
	return retval;
}

static int genl_mpls_labelspace_dump(struct sk_buff *skb,
	struct netlink_callback *cb)
{
	struct net_device *dev;
	int entries_to_skip;
	int entry_count;

	entries_to_skip = cb->args[0];
	entry_count = 0;

	MPLS_DEBUG("Enter: entry %d\n", entries_to_skip);
	read_lock(&dev_base_lock);
	for_each_netdev(&init_net, dev) {
		MPLS_DEBUG("Dump: entry %d\n", entry_count);
		if (entry_count >= entries_to_skip) {
			if (mpls_fill_labelspace(skb, dev,
				NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq,
				NLM_F_MULTI, MPLS_CMD_SETLABELSPACE) < 0) {
				break;
			}
		}
		entry_count++;
	}
	read_unlock(&dev_base_lock);
	cb->args[0] = entry_count;

	MPLS_DEBUG("Exit: entry %d\n", entry_count);
	return skb->len;
}

//add by here for create the tunnel Interface

/* tunnel netlink support */

//static int mpls_fill_tunnel(struct sk_buff *skb, struct net_device *dev,
//	    u32 pid, u32 seq, int flag, int event)
static int mpls_fill_tunnel(struct sk_buff *skb,
	    u32 pid, u32 seq, int flag, int event)
{
	struct mpls_tunnel_req ls;
	void *hdr;

	hdr = genlmsg_put(skb, pid, seq, &genl_mpls, flag, event);
/*
	ls.mls_ifindex = dev->ifindex;
	if (dev->mpls_ptr) {
		ls.mls_labelspace =
			((struct mpls_interface*)dev->mpls_ptr)->labelspace;
	} else {
		ls.mls_labelspace = -1;
	}*/

	nla_put(skb, MPLS_ATTR_TUNNEL, sizeof(ls), &ls);

	MPLS_DEBUG("Exit: length\n");
	return genlmsg_end(skb, hdr);

/*nla_put_failure:
	genlmsg_cancel(skb, hdr);
        MPLS_DEBUG("Exit: -1\n");
        return -ENOMEM;*/
}


void mpls_tunnel_event(int event)
{
	struct sk_buff *skb;
	int err;

	MPLS_ENTER;
	skb = nlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (skb == NULL) {
		MPLS_DEBUG("Exit: EINVAL\n");
		return;
	}

	//err = mpls_fill_tunnel(skb, dev, 0, 0, 0, event);
	err = mpls_fill_tunnel(skb, 0, 0, 0, event);
	if (err < 0) {
		nlmsg_free(skb);
		MPLS_DEBUG("Exit: EINVAL\n");
		return;
	}
	genlmsg_multicast(&genl_mpls, skb, 0, 0, GFP_KERNEL);
	MPLS_EXIT;
}

static int genl_mpls_tunnel_add(struct sk_buff *skb, struct genl_info *info)
{
	struct mpls_tunnel_req *tn;
	int retval = -EINVAL;
	MPLS_ENTER;
	tn = nla_data(info->attrs[MPLS_ATTR_TUNNEL]);
	retval = mpls_tunnel_add(tn);
	MPLS_DEBUG("Exit: %d\n", retval);
	return retval;
}
static int genl_mpls_tunnel_del(struct sk_buff *skb, struct genl_info *info)
{
	struct mpls_tunnel_req *tn;
	int retval = -EINVAL;
	MPLS_ENTER;
	tn = nla_data(info->attrs[MPLS_ATTR_TUNNEL]);
	retval = mpls_tunnel_del(tn);
	MPLS_DEBUG("Exit: %d\n", retval);
	return retval;
}
//end by here

static struct nla_policy genl_mpls_policy[MPLS_ATTR_MAX+1] __read_mostly = {
	[MPLS_ATTR_ILM] = { .len = sizeof(struct mpls_in_label_req) },
	[MPLS_ATTR_NHLFE] = { .len = sizeof(struct mpls_out_label_req) },
	[MPLS_ATTR_XC] = { .len = sizeof(struct mpls_xconnect_req) },
	[MPLS_ATTR_LABELSPACE] = {.len = sizeof(struct mpls_labelspace_req)},
	[MPLS_ATTR_TUNNEL] = {.len = sizeof(struct mpls_labelspace_req)},
	[MPLS_ATTR_INSTR] = { .len = sizeof(struct mpls_instr_req) },
	[MPLS_ATTR_STATS] = { .len = sizeof(struct gnet_stats_basic) },
};

static struct genl_ops mpls_genl_ops[] = {
	{
		.cmd		= MPLS_CMD_NEWILM,
		.doit		= genl_mpls_ilm_new,
		.policy		= genl_mpls_policy,
	},
	{
		.cmd		= MPLS_CMD_DELILM,
		.doit		= genl_mpls_ilm_del,
		.policy		= genl_mpls_policy,
	},
	{
		.cmd		= MPLS_CMD_GETILM,
		.doit		= genl_mpls_ilm_get,
		.dumpit		= genl_mpls_ilm_dump,
		.policy		= genl_mpls_policy,
	},
	{
		.cmd		= MPLS_CMD_NEWNHLFE,
		.doit		= genl_mpls_nhlfe_new,
		.policy		= genl_mpls_policy,
	},
	{
		.cmd		= MPLS_CMD_DELNHLFE,
		.doit		= genl_mpls_nhlfe_del,
		.policy		= genl_mpls_policy,
	},
	{
		.cmd		= MPLS_CMD_GETNHLFE,
		.doit		= genl_mpls_nhlfe_get,
		.dumpit		= genl_mpls_nhlfe_dump,
		.policy		= genl_mpls_policy,
	},
	{
		.cmd		= MPLS_CMD_NEWXC,
		.doit		= genl_mpls_xc_new,
		.policy		= genl_mpls_policy,
	},
	{
		.cmd		= MPLS_CMD_DELXC,
		.doit		= genl_mpls_xc_del,
		.policy		= genl_mpls_policy,
	},
	{
		.cmd		= MPLS_CMD_GETXC,
		.doit		= genl_mpls_xc_get,
		.dumpit		= genl_mpls_xc_dump,
		.policy		= genl_mpls_policy,
	},
	{
		.cmd		= MPLS_CMD_SETLABELSPACE,
		.doit		= genl_mpls_labelspace_set,
		.policy		= genl_mpls_policy,
	},
	{
		.cmd		= MPLS_CMD_GETLABELSPACE,
		.doit		= genl_mpls_labelspace_get,
		.dumpit		= genl_mpls_labelspace_dump,
		.policy		= genl_mpls_policy,
	},
	//add by here for create the new tunnel interface
	{
		.cmd		= MPLS_CMD_ADDTUNNEL,
		.doit		= genl_mpls_tunnel_add,
		.policy		= genl_mpls_policy,
	}, 
	{
		.cmd		= MPLS_CMD_DELTUNNEL,
		.doit		= genl_mpls_tunnel_del,
		.policy		= genl_mpls_policy,
	},
	//end by here
};

int __init mpls_netlink_init(void)
{
	int err;

	err = genl_register_family_with_ops_groups(&genl_mpls, mpls_genl_ops, mpls_gnl_mcgrps);
	if (err) {
		printk(MPLS_ERR "MPLS: failed to register with genetlink\n");
		return -EINVAL;
	}

	return 0;

/*errout_register_5:
	//genl_unregister_family(&genl_mpls);
	printk(MPLS_ERR "MPLS: failed to register with genetlink\n");
	return -EINVAL;*/
}

void __exit mpls_netlink_exit(void)
{
	genl_unregister_family(&genl_mpls);
}
