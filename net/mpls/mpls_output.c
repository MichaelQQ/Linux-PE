/*****************************************************************************
 * MPLS
 *      An implementation of the MPLS (MultiProtocol Label
 *      Switching Architecture) for Linux.
 *
 * Authors:
 *          James Leu        <jleu@mindspring.com>
 *          Ramon Casellas   <casellas@infres.enst.fr>
 *
 *   (c) 1999-2004   James Leu        <jleu@mindspring.com>
 *   (c) 2003-2004   Ramon Casellas   <casellas@infres.enst.fr>
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 ****************************************************************************/

#include <generated/autoconf.h>
#include <net/ip.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <net/dst.h>
#include <net/ip_fib.h>
#include <net/mpls.h>
#include <linux/ip.h>
#include <net/dsfield.h>

/**
 *	mpls_send - Send a labelled packet.
 *	@skb: Ready to go socket buffer.
 *	@mtu: MTU of the NHLFE that got us here.
 *
 *	Send the socket buffer to the next hop. It assumes that everything has
 *	been properly set up. In order to forward/send the packet, there are two 
 *	methods, using either:
 *	a) hh->hh_output(skb);
 *	b) skb->dst->neighbour->output(skb);
 *
 *	Please note that this function is only called from mpls_output2, and  
 *	even in the case of a transmission error, the sbk is not freed (it will 
 *	be freed by the caller).
 *	Returns: MPLS_RESULT_SUCCESS or MPLS_RESULT_DROP
 **/

static int 
mpls_send (struct sk_buff *skb, int mtu) 
{
	int retval = MPLS_RESULT_SUCCESS;
	struct mpls_prot_driver *prot = MPLSCB(skb)->prot;
	struct neighbour *n = NULL;

	if (MPLSCB(skb)->popped_bos) {
		if (MPLSCB(skb)->ttl < MPLSCB(skb)->prot->get_ttl(skb)) {
			prot->set_ttl(skb, MPLSCB(skb)->ttl);
		}
		switch(prot->family) {
			case AF_INET:
				skb->protocol = htons(ETH_P_IP);
				break;
			case AF_INET6:
				skb->protocol = htons(ETH_P_IPV6);
				break;
			case AF_PACKET:
				skb->protocol = 0;
				skb->mac_header = skb->network_header;
				break;
			default:
				MPLS_ASSERT(0);
		}
	} else {
		skb->protocol = htons(ETH_P_MPLS_UC);
	}

	MPLS_DEBUG("output device = %s\n",skb->dev->name);

#ifdef WE_NEED_TO_FIX_HH_HEADER_BEFORE_SENDING
	mpls_finish(skb);
#endif
	MPLS_DEBUG_CALL(mpls_skb_dump(skb));

	if (skb->len > skb_dst(skb)->dev->mtu) {

		printk("MPLS: packet exceeded MTU %d > %d (%d)\n", skb->len,
		    skb->dev->mtu, mtu);

		retval = prot->mtu_exceeded(&skb, mtu);

		if (retval)
			goto mpls_send_exit;

		/* otherwise prot->mtu_exceeded() has returned a
		 * modified skb that it wants to be forwarded
		 * down the LSP
		 */
	}

        if (unlikely(skb->protocol &&
		(skb_headroom(skb) < LL_RESERVED_SPACE(skb_dst(skb)->dev)) &&
		skb_dst(skb)->dev->header_ops)) {
		struct sk_buff *skb2;

		MPLS_DEBUG("alloc'ing more headroom\n");
		if (!(skb2 = skb_realloc_headroom(skb,
			LL_RESERVED_SPACE(skb_dst(skb)->dev)))) {
			retval = MPLS_RESULT_DROP;
			goto mpls_send_exit;
                }
		if (skb->sk)
			skb_set_owner_w(skb2, skb->sk);
		kfree_skb(skb);
		skb = skb2;
        }

        printk("gap = %u\n",MPLSCB(skb)->gap);
        printk("label = %u\n",MPLSCB(skb)->label);
        printk("ttl = %u\n",MPLSCB(skb)->ttl);
        printk("exp = %u\n",MPLSCB(skb)->exp);
        printk("bos = %u\n",MPLSCB(skb)->bos);
        printk("flag = %d\n",MPLSCB(skb)->flag);
        printk("popped_bos = %d\n",MPLSCB(skb)->popped_bos);

	skb_dst(skb)->dev->netdev_ops->ndo_start_xmit(skb,skb_dst(skb)->dev);
	/*
	if(n) {
		MPLS_DEBUG("using neighbour (%p)\n",skb);
		//n->output(n, skb);
	} else {
		MPLS_DEBUG("no hh no neighbor!?\n");
		retval = MPLS_RESULT_DROP;
	}*/
mpls_send_exit:
	MPLS_DEBUG("mpls_send result %d\n",retval);
	return retval;
}

/**
 *	mpls_output2 - Apply out segment to socket buffer 
 *	@sbk: Socket buffer.
 *	@nhlfe: NHLFE object containint the list of opcodes to apply.
 *
 *	This function is either called by mpls_input or mpls_output, and 
 *	iterates the set of output opcodes that are configured for this nhlfe.
 **/

int mpls_output2 (struct sk_buff *skb,struct mpls_nhlfe *nhlfe)
{
	struct mpls_instr *mi;
	int result = 0;
	int ready_to_tx = 0;
	int mtu = nhlfe->nhlfe_mtu;

	MPLS_OUT_OPCODE_PROTOTYPE(*func);

	MPLS_ENTER;

	/*
	 * about to mangle skb, prepare it for writing and
	 * make sure headroom has space for mac header and shim
	 *
	 * ideally we would know how many shims we will add
	 * and what the eventual tx interface link layer header
	 * size will be
	 *
	 * maybe look at nhlfe_mtu?
	 */
	if (skb_cow(skb, SKB_DATA_ALIGN(skb->mac_len + 4))) {
		goto mpls_output2_drop;
	}

// Support of rec. output 
mpls_output2_start:
	ready_to_tx = 0;
	nhlfe->nhlfe_stats.packets++;
	nhlfe->nhlfe_stats.bytes += skb->len;

	if(!nhlfe->nhlfe_instr)
		goto mpls_output2_drop;
	

	// Iterate all the opcodes for this NHLFE 
	for (mi = nhlfe->nhlfe_instr; mi; mi = mi->mi_next) {
		int opcode = mi->mi_opcode;
		void* data = mi->mi_data;
		char* msg  = mpls_ops[opcode].msg;
		MPLS_DEBUG("opcode %s\n",msg);

		if (mpls_ops[opcode].extra) {
			ready_to_tx = 1;
		}

		if ((func = mpls_ops[opcode].out)) {
			switch ( func (&skb,NULL,&nhlfe,data)) {
				case MPLS_RESULT_RECURSE:
				case MPLS_RESULT_DLV:
				case MPLS_RESULT_DROP:
					goto mpls_output2_drop;
				case MPLS_RESULT_FWD:
					goto mpls_output2_start;
				case MPLS_RESULT_SUCCESS:
					break;
			}
		}
	}

	// 
	// The control plane should have let the opcodes in a coherent
	// state. The last one should have enabled tx. 
	//
	if (!ready_to_tx) 
		goto mpls_output2_drop;

	//
	// Actually do the forwarding
	//
	result = mpls_send (skb, mtu);
	
	if (result != MPLS_RESULT_SUCCESS)
		goto mpls_output2_drop;

	MPLS_EXIT;
	return NET_XMIT_SUCCESS;

mpls_output2_drop:
	MPLS_DEBUG("FWD F'ed up instruction!\n");
	if (nhlfe) 
		nhlfe->nhlfe_drops++;
	kfree_skb(skb);
	MPLS_EXIT;
	return NET_XMIT_DROP;
}

/**
 *	mpls_output_shim - Push a label entry and send the packet.
 *	@skb: socket buffer.
 *	@nhlfe: NHLFE object to apply.
 *
 *	This function is *only* called by mpls_output, and calls 
 *	mpls_output2 with a MPLS "push data" struct filled up 
 *	with default values. The "bottom of stack" flag is asserted.
 **/

int mpls_output_shim (struct sk_buff *skb, struct mpls_nhlfe *nhlfe)
{
	struct mpls_prot_driver *prot;
	int retval = 0;
	int ttl;

	prot = mpls_proto_find_by_ethertype(skb->protocol);
	if (unlikely(!prot)) {
		printk("MPLS: unable to find a protocol driver(%d)\n",
			htons(skb->protocol));
		goto mpls_output_error;
	}

	/*
	 * JLEU: we only propagate the TTL if the SKB came from
	 * IP[46] _and_ nhlfe_propagate_ttl is set to 1, otherwise we
	 * set the TTL sysctl_mpls_default_ttl
	 */
	ttl = sysctl_mpls_default_ttl;
	if (nhlfe->nhlfe_propagate_ttl) {
		ttl = prot->get_ttl(skb);
	}

	MPLSCB(skb)->prot = prot;
	MPLSCB(skb)->label = 0;
	MPLSCB(skb)->ttl = ttl;
	MPLSCB(skb)->exp = 0;
	MPLSCB(skb)->bos = 1;
	MPLSCB(skb)->flag = 0;
	MPLSCB(skb)->popped_bos = 1;
	MPLSCB(skb)->gap = 0;

	retval = mpls_output2(skb,nhlfe);
	/* release since we held above and the packet is now gone */
	mpls_proto_release(prot);
	return retval;

mpls_output_error:
	kfree_skb(skb);
	return NET_XMIT_DROP;
}



/**
 *	mpls_output - Send a packet using MPLS forwarding.
 *	@skb: socket buffer containing the packet to send.
 *
 *	This function is called by the upper layers, in order to 
 *	forward a data packet using MPLS. It assumes that the buffer
 *	is ready, most notably, that skb_dst(skb) field is valid and
 *	is part of a valid NHLFE. After some error checking, calls 
 *	mpls_output_shim. 
 *
 *	NOTE: Please note that we *push* a label. A cross-connect (SWAP)
 *	is a ILM/POP + NHLFE/PUSH
 **/

int mpls_output (struct sk_buff *skb) 
{
	struct mpls_nhlfe* nhlfe = NULL;

	MPLS_ENTER;

	if (unlikely(!skb_dst(skb))) {
		printk("MPLS: No dst in skb\n");
		goto mpls_output_drop;
	}
	if (unlikely(skb_dst(skb)->ops->protocol != htons(ETH_P_MPLS_UC))) {
		printk("MPLS: Not a MPLS dst in skb\n");
		goto mpls_output_drop;
	}
	nhlfe = container_of(skb_dst(skb), struct mpls_nhlfe, u.dst);
	if (unlikely(!nhlfe)) {
		printk("MPLS: unable to find NHLFE from dst\n");
		goto mpls_output_drop;
	}

	/* we do the 'share' here, because, Layer 3 enters via this function,
	 * and we only have to worry about 'sharing' when the packet came from
	 * a layer 3 protocol
	 */
	skb = skb_share_check(skb, GFP_ATOMIC);
	if (unlikely(!skb)) {
		printk("MPLS: unable to share skb\n");
		goto mpls_output_drop;
	}

	/*
	 * if this packet thinks the hardware is going to do the
	 * checksum, it had better think again.  By the time this
	 * packet makes it to the hardware, it will be an MPLS packet
	 * and the IP packet will mearly be the MPLS payload.
	 * The hardware will not know how to add a checksum to the
	 * payload of a MPLS packet ....
	 */
	if (skb->ip_summed == CHECKSUM_COMPLETE) {
		if (skb_checksum_help(skb))
			goto mpls_output_drop;
	}

	MPLS_EXIT;
	return mpls_output_shim(skb,nhlfe);

mpls_output_drop:
	kfree_skb(skb);
	MPLS_EXIT;
	return NET_XMIT_DROP;
}

/**
 *	mpls_switch - Label switch a packet coming from mpls_input
 *	@skb: socket buffer containing the packet to send.
 *
 *	This function is called by mpls_input, in order to 
 *	label switch a data packet. It assumes that the socket
 *	is ready, most notably, that skb_dst(skb) field is valid and
 *	is part of a valid NHLFE. After some error checking, calls 
 *	mpls_output2. 
 *	NOTE: Please note that we *push* a label. The current label was
 *	already poped in mpls_input.
 **/
int mpls_switch (struct sk_buff *skb) 
{
	struct mpls_nhlfe* nhlfe = NULL;
	struct mpls_prot_driver *prot;
	int retval;

	if (unlikely(!skb_dst(skb))) {
		printk("MPLS: No dst in skb\n");
		goto mpls_switch_drop;
	}
	if (unlikely(skb_dst(skb)->ops->protocol != htons(ETH_P_MPLS_UC))) {
		printk("MPLS: Not a MPLS dst in skb\n");
		goto mpls_switch_drop;
	}
	nhlfe = container_of(skb_dst(skb), struct mpls_nhlfe, u.dst);
	if (unlikely(!nhlfe)) {
		printk("MPLS: unable to find NHLFE from dst\n");
		goto mpls_switch_drop;
	}

	prot = MPLSCB(skb)->prot;
	retval = mpls_output2(skb,nhlfe);
	/* mpls_input() does a mpls_proto_hold() */
	mpls_proto_release(prot);
	return retval;

mpls_switch_drop:
	kfree_skb(skb);
	return NET_XMIT_DROP;
}

EXPORT_SYMBOL(mpls_output2);
EXPORT_SYMBOL(mpls_output_shim);
