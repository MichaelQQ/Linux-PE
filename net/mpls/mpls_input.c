--- mpls-linux-2.6.35.y/net/mpls/mpls_input.c	1970-01-01 08:00:00.000000000 +0800
+++ linux-2.6.35-vpls/net/mpls/mpls_input.c	2015-04-20 20:24:43.759583630 +0800
@@ -0,0 +1,305 @@
+/*****************************************************************************
+ *	MPLS
+ *	     An implementation of the MPLS (MultiProtocol Label
+ *	     Switching Architecture) for Linux.
+ *
+ *	Authors:
+ *	         James Leu        <jleu@mindspring.com>
+ *	         Ramon Casellas   <casellas@infres.enst.fr>
+ *
+ *	  (c) 1999-2004   James Leu        <jleu@mindspring.com>
+ *	  (c) 2003-2004   Ramon Casellas   <casellas@infres.enst.fr>
+ *
+ *	     This program is free software; you can redistribute it and/or
+ *	     modify it under the terms of the GNU General Public License
+ *	     as published by the Free Software Foundation; either version
+ *	     2 of the License, or (at your option) any later version.
+ ****************************************************************************/
+
+#include <generated/autoconf.h>
+#include <linux/kernel.h>
+#include <linux/netdevice.h>
+#include <linux/mm.h>
+#include <linux/slab.h>
+#include <linux/if_ether.h>
+#include <linux/if_vlan.h>
+#include <linux/if_arp.h>
+#include <linux/kobject.h>
+#include <net/ip.h>
+#include <net/icmp.h>
+#ifdef CONFIG_IPV6
+#include <net/ipv6.h>
+#endif
+#include <net/mpls.h>
+
+
+/**
+ *	mpls_input - Begin labelled packet processing.
+ *	@skb:        socket buffer, containing the good stuff.
+ *	@dev:        device that receives the packet.
+ *	@pt:         packet type (handler) structure.
+ *	@label:      label value + metadata (type)
+ *	@labelspace: incoming labelspace.
+ **/
+
+static int 
+mpls_input (struct sk_buff        *skb, struct net_device *dev,
+            struct packet_type    *pt, struct mpls_label *label,
+	    int labelspace) 
+{
+	MPLS_IN_OPCODE_PROTOTYPE(*func);   /* Function Pointer for Opcodes */
+	struct mpls_prot_driver *prot = NULL;
+	struct mpls_nhlfe *nhlfe = NULL;  /* Current NHLFE                  */
+	struct mpls_ilm  *ilm = NULL;  /* Current ILM                  */
+	struct mpls_instr    *mi  = NULL;
+	void *data = NULL;                 /* current data for opcode      */
+	int  opcode = 0;                   /* Current opcode to execute    */
+	char *msg = NULL;                  /* Human readable desc. opcode  */
+	int retval;
+
+	MPLS_ENTER;
+
+mpls_input_start:
+
+	if (ilm) {
+		/* we only hit this case when we have a recursive label
+		 * lookup.  drop the previous protocol driver, and ilm
+		 */
+		mpls_proto_release(MPLSCB(skb)->prot);
+		mpls_ilm_release(ilm);
+	}
+
+	MPLS_DEBUG("labelspace=%d,label=%d,exp=%01x,B.O.S=%d,TTL=%d\n",
+		labelspace, MPLSCB(skb)->label, MPLSCB(skb)->exp,
+		MPLSCB(skb)->bos, MPLSCB(skb)->ttl);
+
+	/* GET a reference to the ilm given this label value/labelspace*/
+	ilm = mpls_get_ilm_by_label (label, labelspace, MPLSCB(skb)->bos);
+	if (unlikely(!ilm)) {
+		MPLS_DEBUG("unknown incoming label, dropping\n");
+		goto mpls_input_drop;
+	}
+
+	mpls_proto_hold(ilm->ilm_proto);
+	MPLSCB(skb)->prot = ilm->ilm_proto;
+
+	ilm->ilm_stats.packets++;
+	ilm->ilm_stats.bytes += skb->len;
+
+	/* Iterate all the opcodes for this ILM */
+	for (mi = ilm->ilm_instr; mi; mi = mi->mi_next) {
+		data   = mi->mi_data;
+		opcode = mi->mi_opcode;
+		msg    = mpls_ops[opcode].msg;
+		func   = mpls_ops[opcode].in;
+
+		MPLS_DEBUG("opcode %s\n",msg);
+		if (!func) {
+			MPLS_DEBUG("invalid opcode for input: %s\n",msg);
+			goto mpls_input_drop;
+		}
+
+		switch (func(&skb,ilm,&nhlfe,data)) {
+			case MPLS_RESULT_RECURSE:
+				label->ml_type = MPLS_LABEL_GEN;
+				label->u.ml_gen = MPLSCB(skb)->label;
+				goto mpls_input_start;
+			case MPLS_RESULT_DLV:
+				goto mpls_input_dlv;
+			case MPLS_RESULT_FWD:
+				goto mpls_input_fwd;
+			case MPLS_RESULT_DROP:
+				mpls_proto_release(MPLSCB(skb)->prot);
+				goto mpls_input_drop;
+			case MPLS_RESULT_SUCCESS:
+				break;
+		}
+	}
+	MPLS_DEBUG("finished executing in label program without DLV or FWD\n");
+	mpls_proto_release(MPLSCB(skb)->prot);
+
+	/* fall through to drop */
+
+mpls_input_drop:
+
+	/* proto driver isn't held yet, no need to release it */
+	if (ilm) {
+		ilm->ilm_drops++;
+		mpls_ilm_release(ilm);
+	}
+	MPLS_DEBUG("dropped\n");
+	return NET_RX_DROP;
+
+mpls_input_dlv:
+
+	dst_hold(&ilm->u.dst);
+	skb_dst_set(skb, &ilm->u.dst);
+
+	/*
+	 * clean up the packet so that protocols like DHCP
+	 * will work across a LSP
+	 */
+	if (ilm->ilm_fix_hh) {
+		if (mpls_finish(skb) == NULL) {
+			MPLS_DEBUG("unable to finish skb\n");
+			return NET_RX_DROP;
+		}
+	}
+
+	mpls_ilm_release(ilm);
+
+	/* ala Cisco, take the lesser of the TTLs
+	 * -if propogate TTL was done at the ingress LER, then the
+	 *  shim TTL will be less the the header TTL
+	 * -if no propogate TTL was done as the ingress LER, a
+	 *  default TTL was placed in the shim, which makes the
+	 *  entire length of the LSP look like one hop to traceroute.
+	 *  As long as the default value placed in the shim is
+	 *  significantly larger then the TTL in the header, then
+	 *  traceroute will work fine.  If not, then traceroute
+	 *  will continualy show the egress of the LSP as the
+	 *  next hop in the path.
+	 */
+	
+	if (MPLSCB(skb)->ttl < MPLSCB(skb)->prot->get_ttl(skb)) {
+		MPLSCB(skb)->prot->set_ttl(skb, MPLSCB(skb)->ttl);
+	}
+
+	/* we're done with the PDU, it now goes to another layer for handling
+	 * it is safe to release the protocol driver now
+	 */
+	mpls_proto_release(MPLSCB(skb)->prot);
+
+	MPLS_DEBUG("delivering\n");
+
+	return 0;
+
+mpls_input_fwd:
+
+	mpls_ilm_release (ilm);
+
+	if (MPLSCB(skb)->ttl <= 1) {
+		printk("TTL exceeded\n");
+
+		prot = MPLSCB(skb)->prot;
+		retval = prot->ttl_expired(&skb);
+		mpls_proto_release(prot);
+
+		if (retval)
+			return retval;
+
+		/* otherwise prot->ttl_expired() must have modified the
+		 * skb and want it to be forwarded down the LSP
+		 */
+	}
+	
+	(MPLSCB(skb)->ttl)--;
+
+	dst_hold(&nhlfe->u.dst);
+	skb_dst_set(skb, &nhlfe->u.dst);
+
+	/* mpls_switch() does a mpls_proto_release() */
+
+	MPLS_DEBUG("switching\n");
+
+	return 0;
+}
+
+/**
+ *	mpls_skb_recv - Main MPLS packet receive function.
+ *	@skb : socket buffer, containing the good stuff.
+ *	@dev : device that receives the packet.
+ *	@pt  : packet type handler.
+ **/
+
+int 
+mpls_skb_recv (
+	struct sk_buff     *skb, 
+	struct net_device  *dev,
+	struct packet_type *pt,
+	struct net_device  *orig)
+{
+	int labelspace;
+	int result = NET_RX_DROP;
+	struct mpls_label label;
+	struct mpls_interface *mip = mpls_get_if_info(dev->ifindex);
+
+	MPLS_ENTER;
+	MPLS_DEBUG_CALL(mpls_skb_dump(skb));
+
+	if (skb->pkt_type == PACKET_OTHERHOST)
+		goto mpls_rcv_drop;
+
+	if (!(skb = skb_share_check (skb, GFP_ATOMIC)))
+		goto mpls_rcv_out;
+
+	if (!pskb_may_pull (skb, MPLS_SHIM_SIZE))
+		goto mpls_rcv_err;
+
+	labelspace = mip ? mip->labelspace : -1;
+	if (unlikely(labelspace < 0)) {
+		MPLS_DEBUG("unicast packet recv on if. w/o labelspace (%s) - packet dropped\n",dev->name);
+		goto mpls_rcv_drop;
+	}
+
+	memset(MPLSCB(skb), 0, sizeof(*MPLSCB(skb)));
+	memset(&label, 0, sizeof(label));
+	MPLSCB(skb)->top_of_stack = skb->data;
+
+	mpls_opcode_peek (skb);
+
+	/* we need the label struct for when we support ATM and FR */
+	switch(dev->type) {
+		case ARPHRD_ETHER:
+		case ARPHRD_FDDI:
+		case ARPHRD_IEEE802:
+		case ARPHRD_PPP:
+		case ARPHRD_LOOPBACK:
+		case ARPHRD_HDLC:
+		case ARPHRD_IPGRE:
+			label.ml_type  = MPLS_LABEL_GEN;
+			label.u.ml_gen = MPLSCB(skb)->label;
+			break;
+		default:
+			printk("Unknown IfType(%08x) for MPLS\n",dev->type);
+			goto mpls_rcv_err;
+	}
+
+	if (mpls_input (skb,dev,pt,&label,labelspace))
+		goto mpls_rcv_drop;
+
+	result = dst_input(skb);
+
+	MPLS_DEBUG("exit(%d)\n",result);
+	return result;
+
+mpls_rcv_err:
+	/* increment some err counter */
+mpls_rcv_drop:
+	kfree_skb (skb);
+mpls_rcv_out:
+	MPLS_DEBUG("exit(DROP)\n");
+	return NET_RX_DROP;
+}
+
+
+
+
+
+/**
+ *	mpls_skb_recv_mc - Main Multicast MPLS packet receive function.
+ *	@skb : socket buffer, containing the good stuff.
+ *	@dev : device that receives the packet.
+ *	@pt  : packet handler. (MPLS UC)
+ **/
+
+int mpls_skb_recv_mc (
+	struct sk_buff     *skb,
+	struct net_device  *dev,
+	struct packet_type *pt,
+	struct net_device  *orig)
+{
+	kfree_skb(skb);
+	MPLS_DEBUG("Not implemented\n");
+	return NET_RX_DROP;
+}
