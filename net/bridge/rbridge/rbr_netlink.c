#include <net/genetlink.h>
#include <net/netlink.h>
#include <linux/if_trill.h>
#include "rbr_netlink.h"

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
  /* TODO */
  return 0;
}

static int trill_cmd_get_rbridge(struct sk_buff *skb, struct genl_info *info){
  /* TODO */
  return 0;
}

static int trill_cmd_set_rbridge(struct sk_buff *skb, struct genl_info *info){
  /* TODO */
  return 0;
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