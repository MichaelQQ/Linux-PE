#include <net/genetlink.h>
#include <net/netlink.h>
#include <linux/if_trill.h>
#include <linux/socket.h>
#include "../br_private.h"
#include "rbr_netlink.h"

int trill_genlseqnb = 0; /*sequence number*/

static struct nla_policy TRILL_U16_POLICY [TRILL_ATTR_MAX + 1]={
  [TRILL_ATTR_U16]={.type = NLA_U16},
};
static struct nla_policy TRILL_BIN_POLICY [TRILL_ATTR_MAX + 1]={
  [TRILL_ATTR_BIN]={.type = NLA_UNSPEC},
};
static struct genl_family trill_genl_family = {
  .id = GENL_ID_GENERATE,
  .hdrsize = sizeof(struct trill_nl_header),
  .name = TRILL_NL_FAMILY,
  .version = TRILL_NL_VERSION,
  .maxattr = TRILL_ATTR_MAX
};
static struct genl_multicast_group trill_mcgrp = {
  .name		= TRILL_MCAST_NAME,
};

static int trill_cmd_set_nicks_info(struct sk_buff *skb, struct genl_info *info){
  /* TODO */
  return 0;
}

static int trill_cmd_get_nicks_info(struct sk_buff *skb, struct genl_info *info){
  /* TODO */
  return 0;
}

static int trill_cmd_add_nicks_info(struct sk_buff *skb, struct genl_info *info){
  /* TODO */
  return 0;
}

static int trill_cmd_set_treeroot_id(struct sk_buff *skb, struct genl_info *info){
  int error;
  u16 nickname;
  struct trill_nl_header *trnlhdr;
  struct net_device *source_port = NULL;
  struct net *net = sock_net(skb->sk);
  struct net_bridge_port *p = NULL;
  struct net_bridge *br = NULL;
  trill_genlseqnb = info->snd_seq;
  nickname = nla_get_u16(info->attrs[TRILL_ATTR_U16]);
  trnlhdr = info->userhdr;
  if (trnlhdr->ifindex)
    source_port = __dev_get_by_index(net, trnlhdr->ifindex);
  if (source_port){
    p = br_port_get_rcu(source_port);
    if (p)
    {
	br = p->br;
	if (br)
	{
	  if (br->rbr)
	  {
	    error = set_treeroot(br->rbr, htons(nickname));
	    if (error)
		return -EFAULT;
	    else
		return 0;
	  }
	}
    }
  }
    printk(KERN_WARNING"trill_cmd_set_treeroot_id FAILED\n");
    return -EFAULT;
}

/* trill_cmd_get_rbridge when started daemon inquire for already
 * existant nickname
 * bridge with TRILL capability may already have a nickname
 * is daemon have crashed
 */
static int trill_cmd_get_rbridge(struct sk_buff *skb, struct genl_info *info){
  struct trill_nl_header *trnlhdr;
  struct sk_buff *msg;
  struct net_bridge_port *p;
  struct net_bridge *br;
  struct net_device *source_port=NULL;
  struct net *net = sock_net(skb->sk);
  u16 nickname = RBRIDGE_NICKNAME_NONE;
  trill_genlseqnb = info->snd_seq;
  trnlhdr = info->userhdr;
  if (trnlhdr->ifindex)
    source_port = __dev_get_by_index(net,trnlhdr->ifindex);
  if (source_port){
    p = br_port_get_rcu(source_port);
    if (p)
    {
	br = p->br;
	if (br)
	{
	  if (br->rbr){
	    nickname = ntohs(br->rbr->nick);
	  }
	}
    }
  }
    msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
    trnlhdr = genlmsg_put(msg, info->snd_portid, trill_genlseqnb,
				  &trill_genl_family,
				  sizeof(struct trill_nl_header),
				  TRILL_CMD_GET_RBRIDGE);
    trnlhdr->ifindex = KERNL_RESPONSE_INTERFACE;
    nla_put_u16(msg, TRILL_ATTR_U16, nickname);
    genlmsg_end(msg, trnlhdr);
    return  genlmsg_reply(msg, info);
}

/* trill_cmd_set_rbridge when started daemon set chosen nickname after
 * discovering the topology and ensuring nickname uniqueness
 */
static int trill_cmd_set_rbridge(struct sk_buff *skb, struct genl_info *info){
  u16 nickname;
  struct trill_nl_header *trnlhdr;
  struct net_device *source_port = NULL;
  struct net_bridge_port *p = NULL;
  struct net_bridge *br = NULL;
  struct net *net = sock_net(skb->sk);
  trill_genlseqnb = info->snd_seq;
  trnlhdr = info->userhdr;
  if (trnlhdr->ifindex){
    source_port = __dev_get_by_index(net,trnlhdr->ifindex);
  }
  nickname = nla_get_u16(info->attrs[TRILL_ATTR_U16]);
  if (source_port){
    p = br_port_get_rcu(source_port);
    if (p){
      br = p->br;
      if (br){
	  /* if daemon has started and bridge TRILL capability
	   * is not enabled then start it
	   */
	  if(br->trill_enabled == BR_NO_TRILL)
	    br_trill_set_enabled(br, 1);
	  if (br->rbr){
	    spin_lock_bh(&br->lock);
	    br->rbr->nick = htons(nickname);
	    spin_unlock_bh(&br->lock);
	    return 0;
	  }
      }
    }
  }
  printk(KERN_WARNING"trill_cmd_set_bridge FAILED \n");
  return -EFAULT;
}

static int trill_cmd_port_flush(struct sk_buff *skb, struct genl_info *info){
  /* TODO */
  return 0;
}

static int trill_cmd_nick_flush(struct sk_buff *skb, struct genl_info *info){
  /* TODO */
  return 0;
}

static struct genl_ops trill_genl_ops[] = {
  {
    .cmd = TRILL_CMD_SET_NICKS_INFO,
    .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
    .policy = TRILL_BIN_POLICY,
    .doit = trill_cmd_set_nicks_info,
  },
  {
    .cmd = TRILL_CMD_GET_NICKS_INFO,
    .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
    .policy = TRILL_BIN_POLICY,
    .doit = trill_cmd_get_nicks_info,
  },
  {
    .cmd = TRILL_CMD_ADD_NICKS_INFO,
    .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
    .policy = TRILL_BIN_POLICY,
    .doit = trill_cmd_add_nicks_info,
  },
  {
    .cmd = TRILL_CMD_SET_TREEROOT_ID,
    .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
    .policy = TRILL_U16_POLICY,
    .doit = trill_cmd_set_treeroot_id,
  },
  {
    .cmd = TRILL_CMD_GET_RBRIDGE,
    .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
    .policy = TRILL_U16_POLICY,
    .doit = trill_cmd_get_rbridge,
  },
  {
    .cmd = TRILL_CMD_SET_RBRIDGE,
    .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
    .policy = TRILL_U16_POLICY,
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
    .policy = TRILL_U16_POLICY,
    .doit = trill_cmd_nick_flush,
  },
};
void __exit rbridge_unregister_genl(void){
  int i;
  for (i=0; i<ARRAY_SIZE(trill_genl_ops); i++)
    genl_unregister_ops(&trill_genl_family, &trill_genl_ops[i]);
  genl_unregister_mc_group(&trill_genl_family, &trill_mcgrp);
  genl_unregister_family(&trill_genl_family);
}
int __init rbridge_register_genl(void){
  int err,i;
  err=genl_register_family (&trill_genl_family);
  if (err)
    return err;
  err=genl_register_mc_group(&trill_genl_family, &trill_mcgrp);
  if (err)
    goto fail1;
  for (i=0; i<ARRAY_SIZE(trill_genl_ops); i++)
  err = genl_register_ops(&trill_genl_family,&trill_genl_ops[i]);
  if (err)
    goto fail2;
  else
    goto done;
  fail2:
  genl_unregister_mc_group(&trill_genl_family, &trill_mcgrp);
fail1:
  genl_unregister_family(&trill_genl_family);
done:
  return err;
}