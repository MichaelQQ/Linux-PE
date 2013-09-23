/*
 *	Generic parts
 *	Linux ethernet Rbridge
 *
 *	Authors:
 *	Ahmed AMAMOU		<ahmed@gandi.net>
 *	Kamel Haddadou	<kamel@gandi.net>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include "../br_private.h"
static struct rbr *add_rbr(struct net_bridge *br)
{
  struct rbr *rbr;
  char rbr_name[IFNAMSIZ];
  if (!br->rbr){
    rbr = kzalloc(sizeof(struct rbr), GFP_KERNEL);
    if(!rbr)
	return NULL;
    strcpy(rbr_name, "");
    strncat(rbr_name, br->dev->name, IFNAMSIZ-4);
    strcat(rbr_name, "_rbr");
    spin_lock_bh(&br->lock);
    strncpy(rbr->name, rbr_name, IFNAMSIZ);
    strncpy(rbr->rbr_bridgename, br->dev->name, IFNAMSIZ);
    rbr->br = (struct net_bridge *)br;
    rbr->nick = RBRIDGE_NICKNAME_NONE;
    rbr->treeroot = RBRIDGE_NICKNAME_NONE;
    spin_unlock_bh(&br->lock);
    return rbr;
  }
  else{
    return br->rbr;
  }
}
static void br_trill_start(struct net_bridge *br)
{
	br->rbr = add_rbr(br);
	if(br->rbr){
	  spin_lock_bh(&br->lock);
	  br->trill_enabled = BR_TRILL;
	  spin_unlock_bh(&br->lock);
	}
	else{
	  printk(KERN_WARNING"RBridge allocation for bridge '%s' failed\n",
										br->dev->name);
	}
}

static void br_trill_stop(struct net_bridge *br)
{
	struct rbr * old;
	spin_lock_bh(&br->lock);
	br->trill_enabled = BR_NO_TRILL;
	spin_unlock_bh(&br->lock);
	old = br->rbr;
	br->rbr = NULL;
	if(old)
	{
	  spin_lock_bh(&br->lock);
	  kfree(old);
	  spin_unlock_bh(&br->lock);
	}
}

int set_treeroot(struct rbr *rbr, uint16_t treeroot)
{

	if(!VALID_NICK(treeroot)){
	  pr_warn_ratelimited("rbr_set_treeroot: given tree root not valid\n");
	  goto set_tree_root_fail;
	}
	if (rbr->treeroot != treeroot){
	  spin_lock_bh(&rbr->br->lock);
	  rbr->treeroot = treeroot;
	  spin_unlock_bh(&rbr->br->lock);
	}
	return 0;
set_tree_root_fail:
	return ENOENT;
}

struct rbr_node *rbr_find_node(struct rbr* rbr, __u16 nickname)
{
  struct rbr_node *rbr_node;
  if ( !VALID_NICK(nickname)){
    return NULL;
  }
      rbr_node = rcu_dereference(rbr->rbr_nodes[nickname]);
	rbr_node_get(rbr_node);
	return rbr_node;
}
int rbr_del_node(struct rbr *rbr, uint16_t nickname)
{
  struct rbr_node *rbr_node;
  int ret = ENOENT;
  if (VALID_NICK(nickname)){
    rbr_node = rbr->rbr_nodes[nickname];
    if (rbr_node != NULL){
	rcu_assign_pointer(rbr->rbr_nodes[nickname], NULL);
	rbr_node_put(rbr_node);
	ret = 0;
    }
  }
        return ret;
}
void rbr_del_all(struct rbr *rbr)
{
  int i;
  for (i = RBRIDGE_NICKNAME_MIN; i < RBRIDGE_NICKNAME_MAX; i++) {
    if (rbr->rbr_nodes[i] != NULL)
	(void) rbr_del_node(rbr, i);
  }
}
void br_trill_set_enabled(struct net_bridge *br, unsigned long val)
{
	if (val) {
	  if (br->trill_enabled == BR_NO_TRILL)
	    br_trill_start(br);
	} else {
	  if (br->trill_enabled != BR_NO_TRILL)
	    br_trill_stop(br);
	}
}

/* handling function hook allow handling
 * a frame upon reception called via
 * br_handle_frame_hook = rbr_handle_frame
 * in  br.c
 * Return NULL if skb is handled
 * note: already called with rcu_read_lock (preempt_disabled)
 */
rx_handler_result_t rbr_handle_frame(struct sk_buff **pskb)
{
	struct net_bridge *br;
	struct net_bridge_port *p;
	uint16_t nick= RBRIDGE_NICKNAME_NONE;
	struct sk_buff *skb = *pskb;
	u16 vid = 0;
	p = br_port_get_rcu(skb->dev);
	br=p->br;
	if (!p || p->state == BR_STATE_DISABLED)
	  goto drop;
	/* if trill is not enabled handle by bridge */
	if (br->trill_enabled == BR_NO_TRILL){
		goto handle_by_bridge;
	}else{
		if (unlikely(skb->pkt_type == PACKET_LOOPBACK))
			return RX_HANDLER_PASS;
		skb = skb_share_check(skb, GFP_ATOMIC);
		if (!skb)
			return RX_HANDLER_CONSUMED;
		if (!is_valid_ether_addr(eth_hdr(skb)->h_source)) {
			pr_warn_ratelimited("rbr_handle_frame:invalid src address\n");
			goto drop;
		}
		if (!br_allowed_ingress(p->br, nbp_get_vlan_info(p), skb, &vid))
		  goto drop;
		/* don't forward any BPDU */
		if(is_rbr_address((const u8*)&eth_hdr(skb)->h_dest)){
			br_fdb_update(br, p, eth_hdr(skb)->h_source, vid);
			/* BPDU has to be dropped */
			goto drop;
		}

		if (p->trill_flag != TRILL_FLAG_DISABLE){
		  /* check if destination is connected on the same bridge */
		  if (is_local_guest_port(p, eth_hdr(skb)->h_dest, vid)){
		    struct net_bridge_fdb_entry *dst;
		    dst = __br_fdb_get(br, eth_hdr(skb)->h_dest, vid);
		    if (dst){
		      if (dst->dst->trill_flag != TRILL_FLAG_DISABLE){
			  /* After migration distent vm to local node we need
			   * to remove it nickname
			   */
			  br_fdb_update(br, p, eth_hdr(skb)->h_source, vid);
			  br_deliver(dst->dst, skb);
			  return RX_HANDLER_CONSUMED;
		      }
		    }
		  }
		 /* if packet is from guest port and trill is enabled and dest
		  * is not a guest port encaps it
		  */
		  nick= get_nick_from_mac(p, eth_hdr(skb)->h_dest, vid);
		   /* must update nickname to NONE for guest ports : migration cases */
		  br_fdb_update(br, p, eth_hdr(skb)->h_source, vid);
		  /* TODO encapsulate */
		    return RX_HANDLER_CONSUMED;
		}else{
		      /* packet is not from guest port and trill is enabled */
			if (eth_hdr(skb)->h_proto == __constant_htons(ETH_P_TRILL)) {
				/* TODO trill frame receive handler */
				return RX_HANDLER_CONSUMED;
			}
			else{
			  /* packet is destinated to host port */
			  if (is_local_host_port(p, eth_hdr(skb)->h_dest, vid)){
			    skb->pkt_type = PACKET_HOST;
			    br_handle_frame_finish(skb);
			    return RX_HANDLER_CONSUMED;
			  }
			  /* handle arp */
			  else if (is_broadcast_ether_addr(eth_hdr(skb)->h_dest)){
			    br_fdb_update(br, p, eth_hdr(skb)->h_source, vid);
			    rbr_handle_ether_frame_finish(skb);
			    return RX_HANDLER_CONSUMED;
			  }
			  else{
			    /* packet is not from trill type drop it */
			    goto drop;
			  }
			}
		}
	}
drop:
	if (skb)
	    kfree_skb(skb);
	return RX_HANDLER_CONSUMED;
handle_by_bridge:
	/*packet is not from trill type return to standard bridge frame handle hook*/
	return br_handle_frame(pskb);
}
