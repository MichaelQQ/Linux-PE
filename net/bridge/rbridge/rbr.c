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

static bool rbr_encaps(struct sk_buff *skb,
						uint16_t ingressnick,
						uint16_t egressnick,
						bool multidest)
{
  struct trill_hdr *trh;
  size_t trhsize;
  u16 trill_flags = 0;
  trhsize = sizeof(struct trill_hdr);
  if (!skb->encapsulation) {
    skb_push(skb,ETH_HLEN);
    skb_reset_inner_headers(skb);
    skb->encapsulation = 1;
  }
  if (skb_cow_head(skb, trhsize + ETH_HLEN))
  {
    printk(KERN_ERR "rbr_encaps: cow_head failed\n");
    return 1;
  }
  trh = (struct trill_hdr *) skb_push(skb, sizeof(*trh));
  trill_flags = trill_flags |
		  trill_set_version(TRILL_PROTOCOL_VERS) |
		  trill_set_hopcount(TRILL_DEFAULT_HOPS) |
		  trill_set_multidest(multidest ? 1 : 0);
  trh->th_flags = htons(trill_flags);
  trh->th_egressnick = egressnick;
  trh->th_ingressnick = ingressnick; /* self nick name */
  skb_push(skb, ETH_HLEN); /* make skb->mac_header point to outer mac header */
  skb_reset_mac_header(skb); /* instead of the inner one */
  eth_hdr(skb)->h_proto = __constant_htons(ETH_P_TRILL);
  /* make skb->data point to the right place (just after ether header) */
  skb_pull(skb, ETH_HLEN);
  skb_reset_mac_len(skb);
  return 0;
}
static void rbr_encaps_prepare(struct sk_buff *skb, uint16_t egressnick, u16 vid){
	uint16_t local_nick;
	uint16_t dtrNick;
	struct rbr_node *self;
	struct sk_buff *skb2;
	struct rbr *rbr;
	struct net_bridge_port *p;
	p = br_port_get_rcu(skb->dev);
	if (!p || p->state == BR_STATE_DISABLED){
	  pr_warn_ratelimited("rbr_encaps_prepare: port error\n");
	  goto encaps_drop;
	}
	else{
	  rbr = p->br->rbr;
	}
	/*test if SKB still exist if not no need to do anything*/
	if (skb == NULL)
		return;
	if (egressnick != RBRIDGE_NICKNAME_NONE && !VALID_NICK(egressnick)){
	  pr_warn_ratelimited("rbr_encaps_prepare: invalid destinaton nickname\n");
	  goto encaps_drop;
	}
	local_nick = rbr->nick;
	if (!VALID_NICK(local_nick)){
	  pr_warn_ratelimited("rbr_encaps_prepare: invalid local nickname\n");
	  goto encaps_drop;
	}
	if (egressnick == RBRIDGE_NICKNAME_NONE) {
	  /* Daemon has not yet sent the local nickname */
		if ((self= rbr_find_node(rbr,local_nick))== NULL){
		  pr_warn_ratelimited("rbr_encaps_prepare: waiting for nickname\n");
		  goto encaps_drop;
		}
		if(self->rbr_ni->dtrootcount > 0 )
		  dtrNick = RBR_NI_DTROOTNICK(self->rbr_ni, 0);
		else
		  dtrNick = rbr->treeroot;
		rbr_node_put(self);
		if (!VALID_NICK(dtrNick)){
		  pr_warn_ratelimited("rbr_encaps_prepare: dtrNick is unvalid\n");
		  goto encaps_drop;
		}
		if ((skb2 = skb_clone(skb, GFP_ATOMIC)) == NULL) {
			p->br->dev->stats.tx_dropped++;
			pr_warn_ratelimited("rbr_encaps_prepare: skb_clone failed \n");
			goto encaps_drop;
		}
		br_flood_deliver_vif(p->br, skb2);
		if(rbr_encaps(skb, local_nick, dtrNick, 1))
		  goto encaps_drop;
		/* TODO multi forwarding  */
	}
	else
	{
	  if(rbr_encaps(skb, local_nick, egressnick, 0))
	    goto encaps_drop;
	  /* TODO simple forwarding */
	}
	return;

encaps_drop:
  if (skb)
     kfree_skb(skb);
  return;
}

static int rbr_decap_finish(struct sk_buff *skb, u16 vid)
{
  struct net_bridge *br;
  const unsigned char *dest = eth_hdr(skb)->h_dest;
  struct net_bridge_fdb_entry *dst;
  struct net_device *dev = skb->dev;
  br = netdev_priv(dev);
  dst = __br_fdb_get(br, dest, vid);
  if (dst){
	br_deliver(dst->dst, skb);
  }
  else{
    br_flood_deliver_vif(br, skb);
  }
   return 0;
}
static void rbr_decaps(struct net_bridge_port *p,
			     struct sk_buff *skb,
			     size_t trhsize, u16 vid)
{
  struct trill_hdr *trh;
  struct ethhdr *hdr;
  if (skb == NULL)
    return;
  if (p == NULL)
    return;
  trh = (struct trill_hdr *)skb->data;
  skb_pull(skb, trhsize);
  skb_reset_mac_header(skb);  /* instead of the inner one */
  skb->protocol = eth_hdr(skb)->h_proto;
  hdr = (struct ethhdr*)skb->data;
  skb_pull(skb, ETH_HLEN);
  skb_reset_network_header(skb);
  if (skb->encapsulation)
    skb->encapsulation = 0;
  /* Mark bridge as source device */
  skb->dev = p->br->dev;
  br_fdb_update_nick(p->br, p, hdr->h_source, vid, trh->th_ingressnick);
  rbr_decap_finish(skb, vid);
}
static void rbr_recv(struct sk_buff *skb, u16 vid){
	uint16_t local_nick, dtrNick, adjnick, idx;
	struct rbr *rbr;
	uint8_t srcaddr[ETH_ALEN];
	struct trill_hdr *trh;
	size_t trhsize;
	struct net_bridge_port *p ;
	u16 trill_flags;
	struct sk_buff *skb2;
	struct rbr_node *dest = NULL;
	struct rbr_node *source_node = NULL;
	struct rbr_node *adj = NULL;

	if (skb == NULL)
		return;
	p = br_port_get_rcu(skb->dev);
	if (!p || p->state == BR_STATE_DISABLED){
	  pr_warn_ratelimited("rbr_recv: port error\n");
	  goto recv_drop;
	}
	else{
	  rbr = p->br->rbr;
	}
	memcpy(srcaddr, eth_hdr(skb)->h_source, ETH_ALEN);
	trh = (struct trill_hdr *)skb->data;
	trill_flags = ntohs(trh->th_flags);
	trhsize = sizeof(struct trill_hdr) + trill_get_optslen(trill_flags);
	if (skb->len < trhsize + ETH_HLEN) {
	  pr_warn_ratelimited("rbr_recv:sk_buff len is less then minimal len\n");
	  goto recv_drop;
	}
	if (!skb->encapsulation) {
	  skb_pull(skb,trhsize + ETH_HLEN);
	  skb_reset_inner_headers(skb);
	  skb->encapsulation = 1;
	  skb_push(skb,trhsize + ETH_HLEN);
	}
	if (!VALID_NICK(trh->th_ingressnick) || (!VALID_NICK(trh->th_egressnick)))
	{
	  pr_warn_ratelimited("rbr_recv: invalid nickname \n");
	  goto recv_drop;
	}

	if( trill_get_version(trill_flags) != TRILL_PROTOCOL_VERS) {
	      pr_warn_ratelimited("rbr_recv: not the same trill version\n");
		goto recv_drop;
	}
	local_nick = rbr->nick;
	dtrNick = rbr->treeroot;
	if (trh->th_ingressnick == local_nick){
	  pr_warn_ratelimited("rbr_recv:looping back frame check your config\n");
	  goto recv_drop;
	}
	if (trill_get_optslen(trill_flags)){
	  pr_warn_ratelimited("Found unknown TRILL header extension\n");
	  goto recv_drop;
	  }

	if (!trill_get_multidest(trill_flags)) {
	      /* ntohs not needed as the 2 are in the same bit form */
		if (trh->th_egressnick == trh->th_ingressnick)
		  {
		    pr_warn_ratelimited("rbr_recv: egressnick == ingressnick\n");
		    goto recv_drop;
		  }
		if (trh->th_egressnick == local_nick) {
		  rbr_decaps(p, skb, trhsize, vid);
		}
		else if (trill_get_hopcount(trill_flags)) {
			br_fdb_update(p->br, p, srcaddr, vid);
			/* TODO simple forwarding */
		} else{
		  pr_warn_ratelimited("rbr_recv: hop count limit reached\n");
		  goto recv_drop;
		}
		return;
	}

	 /* Multi-destination frame:
	 * Check if received  multi-destination frame from an
	 * adjacency in the distribution tree rooted at egress nick
	 * indicated in the frame header
	 */

	dest = rbr_find_node(rbr, trh->th_egressnick);
	if(dest == NULL){
	  pr_warn_ratelimited("rbr_recv: mulicast  with unknown destination\n");
	  goto recv_drop;
	}
	for (idx = 0; idx < dest->rbr_ni->adjcount; idx++) {
		adjnick = RBR_NI_ADJNICK(dest->rbr_ni, idx);
		adj = rbr_find_node(rbr, adjnick);
		if (adj == NULL){
			continue;
		}
		if (memcmp(adj->rbr_ni->adjsnpa, srcaddr, ETH_ALEN) == 0) {
			rbr_node_put(adj);
			break;
		}
		rbr_node_put(adj);
	}

	if (idx >= dest->rbr_ni->adjcount) {
	  pr_warn_ratelimited("rbr_recv: multicast unknow mac source\n");
	  rbr_node_put(dest);
	  goto recv_drop;
	}

	/* Reverse path forwarding check.
	 * Check if the ingress RBridge  that has forwarded
	 * the frame advertised the use of the distribution tree specified
	 * in the egress nick
	 */
	source_node = rbr_find_node(rbr, trh->th_ingressnick);
	if (source_node == NULL){
	  pr_warn_ratelimited("rbr_recv: reverse path forwarding check failed\n");
	  rbr_node_put(dest);
	  goto recv_drop;
	}
	for (idx = 0; idx < source_node->rbr_ni->dtrootcount; idx++) {
	  if (RBR_NI_DTROOTNICK(source_node->rbr_ni, idx) ==
		    trh->th_egressnick)
			break;
	}

	if (idx >= source_node->rbr_ni->dtrootcount) {

		/* Allow receipt of forwarded frame with the highest
		 * tree root RBridge as the egress RBridge when the
		 * ingress RBridge has not advertised the use of any
		 * distribution trees.
		 */
		if (source_node->rbr_ni->dtrootcount != 0 ||
		    trh->th_egressnick != dtrNick) {
			rbr_node_put(source_node);
			rbr_node_put(dest);
			goto recv_drop;
		}
	}

	/* Check hop count before doing any forwarding */

	if (trill_get_hopcount(trill_flags) == 0){
	  pr_warn_ratelimited("rbr_recv:multicast hop ount limit reached\n");
	  rbr_node_put(dest);
	  goto recv_drop;
	}
	/* Forward frame using the distribution tree specified by egress nick */
	rbr_node_put(source_node);
	rbr_node_put(dest);

        /* skb2 will be multi forwarded and skb will be locally decaps */
	if ((skb2 = skb_clone(skb, GFP_ATOMIC)) == NULL) {
		p->br->dev->stats.tx_dropped++;
		pr_warn_ratelimited("rbr_recv: multicast skb_clone failed\n");
		goto recv_drop;
	}

	/* TODO multi forwarding  */

	/*
	 * Send de-capsulated frame locally
	 */

	rbr_decaps(p, skb, trhsize, vid);
	return;

recv_drop:
	if (skb)
		kfree_skb(skb);
	return;

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
		  rbr_encaps_prepare(skb, nick, vid);
		  return RX_HANDLER_CONSUMED;
		}else{
		      /* packet is not from guest port and trill is enabled */
			if (eth_hdr(skb)->h_proto == __constant_htons(ETH_P_TRILL)) {
				rbr_recv(skb, vid);
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
