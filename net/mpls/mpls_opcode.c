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
 *
 * Changes:
 *       20031218 JLEU:
 *              Moved per instruction code into mpls_ops
 *	20040120 RCAS:
 *		Formatted and commented opcodes. Changed key access.
 ****************************************************************************/

#include <generated/autoconf.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <net/dst.h>
#include <net/mpls.h>
#include <linux/socket.h>
#include <linux/inetdevice.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <net/arp.h>
#include <net/route.h>
#include <linux/rtnetlink.h>
#include <net/ip_fib.h>
#include <linux/inet.h>
#include <net/net_namespace.h>

/**
 * mpls_finish - Leave the socket buffer in a known (coherent) state.
 * @skb: Socket buffer.
 *
 * In order to optimize socket buffer management, the MPLS implementation
 * manages a "gap", so the common POP-PUSH chain is optimized. This function
 * leaves the socket buffer in a coherent state so things like DHCP
 * will work across a LSP
 **/
 
struct sk_buff *mpls_finish(struct sk_buff *skb) 
{
	unsigned int diff = MPLSCB(skb)->gap;
	MPLS_ENTER;
	if(diff > 0) {
		if (skb_linearize_cow(skb) == 0) {
			memmove(skb->mac_header + diff, skb->mac_header, skb->len);
			skb->mac_header += diff;
			MPLSCB(skb)->gap = 0;
		} else {
			skb = NULL;
		}
	}
	MPLS_EXIT;
	return skb;
}


/**
 * mpls_opcode_peek - Peek the topmost label entry from the stack.
 * @skb: Socket buffer.
 *
 * RCAS: this function should be renamed to mpls_label_entry_peek
 **/
 
int mpls_opcode_peek(struct sk_buff *skb) 
{
	u32 shim;

#define CAN_WE_ASSUME_32BIT_ALIGNED 0
#if CAN_WE_ASSUME_32BIT_ALIGNED
	shim = ntohl(*((u32 *)&skb_network_header(skb)));
#else
	memcpy(&shim, skb_network_header(skb), MPLS_SHIM_SIZE);
	shim = ntohl(shim);
#endif

	if (!(MPLSCB(skb)->flag)) {
		MPLSCB(skb)->ttl  = shim & 0xFF;
		MPLSCB(skb)->flag = 1;
	}
	MPLSCB(skb)->bos   = (shim >> 8 ) & 0x1;
	MPLSCB(skb)->exp   = (shim >> 9 ) & 0x7;
	MPLSCB(skb)->label = (shim >> 12) & 0xFFFFF;

	return MPLS_RESULT_RECURSE;
}

/**
 * mpls_push - push a label entry.
 * @skb: Socket buffer.
 * @ml: label value to push.
 *
 **/
 
int mpls_push (struct sk_buff **skb, struct mpls_label *ml) 
{
	struct sk_buff *o = NULL; 
	struct sk_buff *n = NULL;
	unsigned int label = 0;
	u32 shim;

	MPLS_ENTER;
	o = *skb;
	if (unlikely(!ml)) {
		MPLS_DEBUG("no outgoing label\n");
		return MPLS_RESULT_DROP;
	}

try_again:
	if(likely((MPLSCB(o)->gap >= MPLS_SHIM_SIZE) || (o->data - o->head >= MPLS_SHIM_SIZE))) {
		/*
		 * if we have room between data and end of mac_header
		 * just shift the data,transport_header,network_header pointers and use the room
		 * this would happen if we had a pop previous to this
		 */
		MPLS_DEBUG("using gap\n");
		skb_push(o,MPLS_SHIM_SIZE);
		o->transport_header -= MPLS_SHIM_SIZE;
		o->network_header -= MPLS_SHIM_SIZE;
		MPLSCB(o)->gap -= MPLS_SHIM_SIZE;
		if (MPLSCB(o)->gap < 0) {
			MPLSCB(o)->gap = 0;
		}
	} else {
		/*
		 * we have no room in the inn, go ahead and create a new sk_buff
		 * with enough extra room for one shim
		 */
		MPLS_DEBUG("creating larger packet\n");
		
		if(!(n = skb_realloc_headroom(o, 32))) {
			return MPLS_RESULT_DROP;
		}

		MPLSCB(n)->gap = 0;

		MPLS_DEBUG("dump old packet\n");
		MPLS_DEBUG_CALL(mpls_skb_dump(o));
		kfree_skb(o);

		MPLS_DEBUG("dump new packet\n");
		MPLS_DEBUG_CALL(mpls_skb_dump(n));

		o = *skb = n;

		goto try_again;
	}

	switch(ml->ml_type) {
		case MPLS_LABEL_GEN:
			label = ml->u.ml_gen;
			break;
		default:
			MPLS_DEBUG("invalid label type(%d)\n",ml->ml_type);
			goto push_end;
	}

	/*
	 * no matter what layer 2 we are on, we need the shim! (mpls-encap RFC)
	 */
	shim = htonl(((label & 0xFFFFF) << 12) |
		     ((MPLSCB(o)->exp & 0x7) << 9) |
		     ((MPLSCB(o)->bos & 0x1) << 8) |
		      (MPLSCB(o)->ttl & 0xFF));
	memmove(o->data,&shim,MPLS_SHIM_SIZE);
	MPLSCB(o)->label = label;
	MPLSCB(o)->bos = 0;
	MPLSCB(o)->popped_bos = 0;

push_end:
	MPLS_EXIT;
	return MPLS_RESULT_SUCCESS;;
}


/*
 * Helper functions
 */
 
static inline void 
mpls_list_del_init (struct list_head *entry)
{
	if (!list_empty(entry))
		list_del_init(entry);
}
										
static inline void 
mpls_nhlfe_release_safe (struct mpls_nhlfe *nhlfe)
{
	if (nhlfe)
		mpls_nhlfe_release (nhlfe);
}

/* 
 * Generic function pointer to use when the opcode just
 * needs to free the data pointer
 */
MPLS_CLEAN_OPCODE_PROTOTYPE(mpls_clean_opcode_generic) 
{
	kfree(data);
}


/*********************************************************************
 * MPLS_OP_NOP
 * DESC   : "No operation".
 * EXEC   : mpls_op_nop
 * INPUT  : true
 * OUTPUT : true 
 * DATA   : NULL 
 * LAST   : true 
 *********************************************************************/

MPLS_OPCODE_PROTOTYPE(mpls_op_nop)
{
	return MPLS_RESULT_SUCCESS;
}



/*********************************************************************
 * MPLS_OP_POP
 * DESC   : "Pop label from stack"
 * EXEC   : mpls_in_op_pop
 * BUILD  : mpls_build_opcode_pop
 * UNBUILD: NULL
 * INPUT  : true
 * OUTPUT : false 
 * DATA   : NULL 
 * LAST   : false 
 *********************************************************************/
 
MPLS_IN_OPCODE_PROTOTYPE(mpls_in_op_pop)
{
	/*
	 * Check that we have not popped the last label and
	 * make sure that we can pull
	 */
	if (MPLSCB(*skb)->popped_bos || (((*skb)->data + MPLS_SHIM_SIZE) >= skb_tail_pointer(*skb))) {
		return MPLS_RESULT_DROP;
	}

	/*
	 * Is this the last entry in the stack? then flag it
	 */
	if (MPLSCB(*skb)->bos) {
		MPLSCB(*skb)->popped_bos = 1;
	}

	skb_pull(*skb, MPLS_SHIM_SIZE);
	(*skb)->transport_header     += MPLS_SHIM_SIZE;
	(*skb)->network_header    += MPLS_SHIM_SIZE;
	MPLSCB(*skb)->gap += MPLS_SHIM_SIZE;
	return MPLS_RESULT_SUCCESS;
}


MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_pop) 
{
	*data = NULL;
	if (direction != MPLS_IN) {
		MPLS_DEBUG("POP only valid for incoming labels\n");
		return -EINVAL;
	}
	return 0;
}



/*********************************************************************
 * MPLS_OP_PEEK
 * DESC   : "Peek the contents of the next label entry, no popping"
 * EXEC   : mpls_in_opcode_peek
 * BUILD  : mpls_build_opcode_peek
 * UNBUILD: NULL
 * INPUT  : true
 * OUTPUT : false 
 * DATA   : NULL 
 * LAST   : true 
 *********************************************************************/

MPLS_IN_OPCODE_PROTOTYPE(mpls_in_op_peek)
{
	if (MPLSCB(*skb)->bos) {
		return MPLS_RESULT_DLV;
	}
	mpls_opcode_peek(*skb);
	return MPLS_RESULT_RECURSE;
}


MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_peek) 
{
	*data = NULL;
	if (direction != MPLS_IN) {
		MPLS_DEBUG("PEEK only valid for incoming labels\n");
		return -EINVAL;
	}
	*last_able = 1;
	return 0;
}



/*********************************************************************
 * MPLS_OP_PUSH
 * DESC   : "Push a label entry"
 * EXEC   : mpls_op_push
 * BUILD  : mpls_build_opcode_push
 * UNBUILD: mpls_unbuild_opcode_push
 * CLEAN  : mpls_clean_opcode_push
 * INPUT  : ? 
 * OUTPUT : true 
 * DATA   : Reference to label to push (struct mpls_label*)
 * LAST   : false 
 *********************************************************************/

MPLS_OPCODE_PROTOTYPE(mpls_op_push)
{
	BUG_ON(!data);
	return mpls_push(skb,(struct mpls_label*)data);
}


MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_push) 
{
	struct mpls_label *ml = NULL;

	MPLS_ENTER;
	*data = kmalloc(sizeof(*ml), GFP_ATOMIC);
	if (unlikely(!(*data))) {
		MPLS_DEBUG("error building PUSH label instruction\n");
		MPLS_EXIT;
		return -ENOMEM;
	} 

	ml = _mpls_as_label(*data);
	memcpy(ml,&instr->mir_push, sizeof(*ml));
	(*num_push)++;
	MPLS_EXIT;
	return 0;
}


MPLS_UNBUILD_OPCODE_PROTOTYPE(mpls_unbuild_opcode_push) 
{
	struct mpls_label *ml = NULL;
	MPLS_ENTER;

	ml = data;
	memcpy(&instr->mir_push, ml, sizeof(*ml));

	MPLS_EXIT;
	return 0;
}


MPLS_CLEAN_OPCODE_PROTOTYPE(mpls_clean_opcode_push) 
{
	MPLS_ENTER;
	kfree(data);
	MPLS_EXIT;
}



/*********************************************************************
 * MPLS_OP_DLV
 * DESC   : "Deliver to the upper layers, set skb protocol to ILM's"
 *          "Incoming L3 protocol"
 * EXEC   : mpls_in_opcode_dlv
 * BUILD  : mpls_build_opcode_dlv
 * UNBUILD: NULL
 * INPUT  : true
 * OUTPUT : false 
 * DATA   : NULL 
 * LAST   : true 
 *********************************************************************/

MPLS_IN_OPCODE_PROTOTYPE(mpls_in_op_dlv)
{
	return MPLS_RESULT_DLV;
}



MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_dlv) 
{
	*data = NULL;
	if (unlikely(direction != MPLS_IN)) {
		MPLS_DEBUG("DLV only valid for incoming labels\n");
		return -EINVAL;
	}
	*last_able = 1;
	return 0;
}



/*********************************************************************
 * MPLS_OP_FWD
 * DESC   : "Forward packet, applying a given NHLFE"
 * EXEC   : mpls_op_fwd
 * BUILD  : mpls_build_opcode_fwd
 * UNBUILD: mpls_unbuild_opcode_fwd
 * CLEAN  : mpls_clean_opcode_fwd
 * INPUT  : true
 * OUTPUT : true
 * DATA   : Reference to NHLFE object to apply
 * LAST   : true
 *********************************************************************/

MPLS_OPCODE_PROTOTYPE(mpls_op_fwd)
{
	BUG_ON(!data);
	*nhlfe = (struct mpls_nhlfe*)data;
	return MPLS_RESULT_FWD;
}


MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_fwd) 
{
	struct mpls_nhlfe *nhlfe = NULL;
	unsigned int key = 0;

	MPLS_ENTER;
	*data      = NULL; 
	/* 
	 * Get NHLFE to apply given key
	 */
	key   = mpls_label2key(0, &instr->mir_fwd);
	nhlfe   = mpls_get_nhlfe(key);
	if (unlikely(!nhlfe)) {
		MPLS_DEBUG("FWD: NHLFE key %08x not found\n", key);
		MPLS_EXIT;
		return -ESRCH;
	}

	if (direction == MPLS_OUT) {
		struct mpls_nhlfe *pnhlfe = _mpls_as_nhlfe(parent);
		pnhlfe->nhlfe_mtu = nhlfe->nhlfe_mtu - (4 * (*num_push));
		pnhlfe->nhlfe_mtu_limit = pnhlfe->nhlfe_mtu;
		/* Add parent NHLFE to this NHLFE list */
		list_add(&pnhlfe->nhlfe_entry, &nhlfe->list_out);
	} else {
		struct mpls_ilm *pilm = _mpls_as_ilm(parent);
		/* Add parent ILM to this NHLFE list */
		list_add(&pilm->nhlfe_entry, &nhlfe->list_in);
	}

	*data      = nhlfe; 
	*last_able = 1;
	MPLS_EXIT;
	return 0;
}


MPLS_UNBUILD_OPCODE_PROTOTYPE(mpls_unbuild_opcode_fwd)
{
	struct mpls_nhlfe *nhlfe = NULL;

	MPLS_ENTER;

	nhlfe = data;
	instr->mir_fwd.ml_type = MPLS_LABEL_KEY;
	instr->mir_fwd.u.ml_key = nhlfe->nhlfe_key;

	MPLS_EXIT;
	return 0;
}


MPLS_CLEAN_OPCODE_PROTOTYPE(mpls_clean_opcode_fwd) 
{
	if (direction == MPLS_IN)
		/* Remove parent NHLFE from this NHLFE list */
		mpls_list_del_init(&_mpls_as_ilm(parent)->nhlfe_entry);
	else
		/* Remove parent NHLFE from this NHLFE list */
		mpls_list_del_init(&_mpls_as_nhlfe(parent)->nhlfe_entry);

	mpls_nhlfe_release(_mpls_as_nhlfe(data)); 
}




/*********************************************************************
 * MPLS_OP_NF_FWD
 * DESC   : "Forward packet, applying the NHLFE defined by skbuff mark"
 * EXEC   : mpls_op_nf_fwd
 * BUILD  : mpls_build_opcode_nf_fwd
 * UNBUILD: mpls_unbuild_opcode_nf_fwd
 * CLEAN  : mpls_clean_opcode_nf_fwd
 * INPUT  : false 
 * OUTPUT : true
 * DATA   : NFI object (struct mpls_nfmark_fwd_info*)
 *	o Each nfi_nhlfe element holds a ref to a NHLFE object
 * LAST   : true
 *********************************************************************/

#ifdef CONFIG_NETFILTER

MPLS_OUT_OPCODE_PROTOTYPE(mpls_out_op_nf_fwd)
{
	struct mpls_nfmark_fwd_info *nfi =  data;
	*nhlfe = nfi->nfi_nhlfe[(*skb)->mark & nfi->nfi_mask];
	if (unlikely(!(*nhlfe)))
		return MPLS_RESULT_DROP;
	return MPLS_RESULT_FWD;
}


MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_nf_fwd) 
{
	struct mpls_nfmark_fwd_info *nfi = NULL;
	struct mpls_nhlfe        *nhlfe = NULL;
	unsigned int min_mtu = 0xFFFFFFFF;
	unsigned int key     = 0;
	int j = 0;

	*data = NULL;
	
	/* Allocate NFI object to store in data */
	nfi = kmalloc(sizeof(*nfi),GFP_ATOMIC);
	if (unlikely(!nfi)) {
		MPLS_DEBUG("NF_FWD error building NFMARK info\n");
		return -ENOMEM;
	}
	memset(nfi,0,sizeof(*nfi));

	
	/* Set up NHLFE objects for each mark given the keys */
	nfi->nfi_mask = instr->mir_nf_fwd.nf_mask;
	if (nfi->nfi_mask >= MPLS_NFMARK_NUM) {
		MPLS_DEBUG("NF_FWD mask(%02x) allows too large of values\n",
			nfi->nfi_mask);
		kfree (nfi);
		return -EINVAL;
	}

	for (j=0; j<MPLS_NFMARK_NUM; j++) {
		key = instr->mir_nf_fwd.nf_key[j];
		if (!key) {
			continue;
		}
		nhlfe = mpls_get_nhlfe(key);
		if (unlikely(!nhlfe)) {
			MPLS_DEBUG("NF_FWD: NHLFE - key %08x not found\n", key);
			kfree (nfi);
			return -ESRCH;
		}
		if (nhlfe->nhlfe_mtu < min_mtu) {
			min_mtu = nhlfe->nhlfe_mtu;
		}
		nfi->nfi_nhlfe[j] = nhlfe;
	}

	/* 
	 * Set the MTU according to the number of pushes. 
	 * RCAS :If the opcode is only allowed in output the "if"  should be 
	 * removed, and a check added at the beginning 
	 */
	if (direction == MPLS_OUT) {
		struct mpls_nhlfe *pnhlfe = _mpls_as_nhlfe(parent);
		pnhlfe->nhlfe_mtu = min_mtu - (4 * (*num_push));
		pnhlfe->nhlfe_mtu_limit = pnhlfe->nhlfe_mtu;
	}
	*data = (void*)nfi;
	*last_able = 1;
	return 0;
}

MPLS_UNBUILD_OPCODE_PROTOTYPE(mpls_unbuild_opcode_nf_fwd) 
{
	struct mpls_nfmark_fwd_info *nfi;
	struct mpls_nhlfe *nhlfe;
	unsigned int key;
	int j;

	MPLS_ENTER;
	
	nfi = _mpls_as_nfi(data);
	instr->mir_nf_fwd.nf_mask = nfi->nfi_mask;

	for(j=0;j<MPLS_NFMARK_NUM;j++) {
		nhlfe = nfi->nfi_nhlfe[j];

		key = (nhlfe) ? nhlfe->nhlfe_key : 0;
		instr->mir_nf_fwd.nf_key[j] = key;
	}

	MPLS_EXIT;
	return 0;
}

MPLS_CLEAN_OPCODE_PROTOTYPE(mpls_clean_opcode_nf_fwd) 
{
	int i;
	for (i=0;i<MPLS_NFMARK_NUM;i++) 
		mpls_nhlfe_release_safe(_mpls_as_nfi(data)->nfi_nhlfe[i]);
	kfree(data);
}
#endif




/*********************************************************************
 * MPLS_OP_DS_FWD
 * DESC   : "Forward packet, applying the NHLFE defined by DS field in the"
 *          "encapsulated IPv4/IPv6 packet"
 * EXEC   : mpls_op_ds_fwd
 * BUILD  : mpls_build_opcode_ds_fwd
 * UNBUILD: mpls_unbuild_opcode_ds_fwd
 * CLEAN  : mpls_clean_opcode_ds_fwd
 * INPUT  : false 
 * OUTPUT : true
 * DATA   : DFI object (struct mpls_dsmark_fwd_info*)
 *	o Each dfi_nhlfe element holds a ref to a NHLFE object
 * LAST   : true
 *********************************************************************/

MPLS_OUT_OPCODE_PROTOTYPE(mpls_out_op_ds_fwd)
{
	struct mpls_dsmark_fwd_info *dfi = data;
	unsigned char ds;

	ds = MPLSCB(*skb)->prot->get_dsfield(*skb);

	*nhlfe = dfi->dfi_nhlfe[ds];
	if (unlikely(NULL == *nhlfe))
		return MPLS_RESULT_DROP;

	return MPLS_RESULT_FWD;
}


MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_ds_fwd) 
{
	struct mpls_dsmark_fwd_info *dfi = NULL;
	struct mpls_nhlfe        *nhlfe = NULL;
	unsigned int min_mtu = 0xFFFFFFFF;
	unsigned int key     = 0;
	
	int j = 0;

	*data = NULL;
	/* Allocate DFI object to store in data */
	dfi = kmalloc(sizeof(*dfi),GFP_ATOMIC);
	if (unlikely(!dfi)) {
		MPLS_DEBUG("DS_FWD error building DSMARK info\n");
		return -ENOMEM;
	}
	memset(dfi,0,sizeof(*dfi));
	
	
	/* Set up NHLFE objects for each mark given the keys */
	dfi->dfi_mask = instr->mir_ds_fwd.df_mask;
	if (dfi->dfi_mask >= MPLS_DSMARK_NUM) {
		MPLS_DEBUG("DS_FWD mask(%02x) allows too large of values\n",
			dfi->dfi_mask);
		kfree(dfi);
		return -EINVAL;
	}

	for (j=0; j<MPLS_DSMARK_NUM; j++) {
		key = instr->mir_ds_fwd.df_key[j];
		if (!key) {
			continue;
		}
		nhlfe = mpls_get_nhlfe(key);
		if (unlikely(!nhlfe)) {
			MPLS_DEBUG("DS_FWD: NHLFE key %08x not found\n", key);
			kfree(dfi);
			return -ESRCH;
		}
		if (nhlfe->nhlfe_mtu < min_mtu) {
			min_mtu = nhlfe->nhlfe_mtu;
		}
		dfi->dfi_nhlfe[j] = nhlfe;
	}

	/* 
	 * Set the MTU according to the number of pushes. 
	 * RCAS :If the opcode is only allowed in output the "if"  should be 
	 * removed, and a check added at the beginning 
	 */
	if (direction == MPLS_OUT) {
		struct mpls_nhlfe *pnhlfe = _mpls_as_nhlfe(parent);
		pnhlfe->nhlfe_mtu = min_mtu - (4 * (*num_push));
		pnhlfe->nhlfe_mtu_limit = pnhlfe->nhlfe_mtu;
	}
	*data = (void*)dfi;
	*last_able = 1;
	return 0;
}

MPLS_UNBUILD_OPCODE_PROTOTYPE(mpls_unbuild_opcode_ds_fwd) 
{
	struct mpls_dsmark_fwd_info *dfi;
	struct mpls_nhlfe *nhlfe;
	unsigned int key;
	int j;

	MPLS_ENTER;
	
	dfi = _mpls_as_dfi(data);
	instr->mir_ds_fwd.df_mask = dfi->dfi_mask;

	for(j=0;j<MPLS_DSMARK_NUM;j++) {
		nhlfe = dfi->dfi_nhlfe[j];

		key = (nhlfe) ? nhlfe->nhlfe_key : 0;
		instr->mir_ds_fwd.df_key[j] = key;
	}

	MPLS_EXIT;
	return 0;
}

MPLS_CLEAN_OPCODE_PROTOTYPE(mpls_clean_opcode_ds_fwd) 
{
	int i;
	for (i=0;i<MPLS_DSMARK_NUM;i++) 
		mpls_nhlfe_release_safe(_mpls_as_dfi(data)->dfi_nhlfe[i]);
	kfree(data);
}



/*********************************************************************
 * MPLS_OP_EXP_FWD
 * DESC   : "Forward packet, applying the NHLFE defined by DS the 3 EXP"
 *          "bits in lable entry"
 * EXEC   : mpls_op_exp_fwd
 * BUILD  : mpls_build_opcode_exp_fwd
 * UNBUILD: mpls_unbuild_opcode_exp_fwd
 * CLEAN  : mpls_clean_opcode_exp_fwd
 * INPUT  : true 
 * OUTPUT : true
 * DATA   : EFI object (struct mpls_exp_fwd_info*)
 *	o Each efi_nhlfe element holds a ref to a NHLFE object
 * LAST   : true
 *********************************************************************/

MPLS_OPCODE_PROTOTYPE(mpls_op_exp_fwd)
{
	struct mpls_exp_fwd_info *efi = data;
	/*
	 * Apply the NHLFE defined by the  given 3 EXP bits in label entry
	 */
	*nhlfe = efi->efi_nhlfe[MPLSCB(*skb)->exp & 0x7];
	if (unlikely(NULL == *nhlfe))
		return MPLS_RESULT_DROP;
	return MPLS_RESULT_FWD;
}



MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_exp_fwd) 
{
	struct mpls_exp_fwd_info *efi = NULL;
	struct mpls_nhlfe     *nhlfe = NULL;
	unsigned int min_mtu = 0xFFFFFFFF;
	unsigned int key     = 0;
	int j = 0;

	*data = NULL;
	/* Allocate EFI object to store in data */
	efi = kmalloc(sizeof(*efi),GFP_ATOMIC);
	if (unlikely(!efi)) {
		MPLS_DEBUG("EXP_FWD error building EXP info\n");
		return -ENOMEM;
	}
	memset(efi,0,sizeof(*efi));

	/* Set up NHLFE objects for each EXP value, given the keys */
	for (j=0; j<MPLS_EXP_NUM; j++) {
		key = instr->mir_exp_fwd.ef_key[j];
		if (!key) {
			continue;
		}
		nhlfe = mpls_get_nhlfe(key);
		if (unlikely(!nhlfe)) {
			MPLS_DEBUG("EXP_FWD: NHLFE key %08x not found\n", key);
			kfree(efi);
			return -ESRCH;
		}
		if (nhlfe->nhlfe_mtu < min_mtu) {
			min_mtu = nhlfe->nhlfe_mtu;
		}
		efi->efi_nhlfe[j] = nhlfe;
	}

	/* 
	 * Set the MTU according to the number of pushes. 
	 */
	if (direction == MPLS_OUT) {
		struct mpls_nhlfe *pnhlfe = _mpls_as_nhlfe(parent);
		pnhlfe->nhlfe_mtu = min_mtu - (4 * (*num_push));
		pnhlfe->nhlfe_mtu_limit = pnhlfe->nhlfe_mtu;
	}
	*data = (void*)efi;
	*last_able = 1;
	return 0;
}

MPLS_UNBUILD_OPCODE_PROTOTYPE(mpls_unbuild_opcode_exp_fwd) 
{
	struct mpls_exp_fwd_info *efi;
	struct mpls_nhlfe *nhlfe;
	unsigned int key;
	int j;

	MPLS_ENTER;
	
	efi = _mpls_as_efi(data);

	for(j=0;j<MPLS_EXP_NUM;j++) {
		nhlfe = efi->efi_nhlfe[j];

		key = (nhlfe) ? nhlfe->nhlfe_key : 0;
		instr->mir_exp_fwd.ef_key[j] = key;
	}

	MPLS_EXIT;
	return 0;
}


MPLS_CLEAN_OPCODE_PROTOTYPE(mpls_clean_opcode_exp_fwd) 
{
	int i;
	struct mpls_exp_fwd_info *efi = NULL;
	
	efi = _mpls_as_efi(data);

	/* Release all NHLFEs held in efi (data) */
	for (i=0;i<MPLS_EXP_NUM;i++) 
		mpls_nhlfe_release_safe(efi->efi_nhlfe[i]);

	/* Free the EFI (data) */
	kfree(efi);
}


/*********************************************************************
 * MPLS_OP_SET_RX
 * DESC   : "Artificially change the incoming network device"
 * EXEC   : mpls_in_op_set_rx
 * BUILD  : mpls_build_opcode_set_rx
 * UNBUILD: mpls_unbuild_opcode_set_rx
 * CLEAN  : mpls_clean_opcode_set_rx
 * INPUT  : true 
 * OUTPUT : false 
 * DATA   : Reference to a net_device (struct net_device*)
 * LAST   : false
 * 
 * Remark : If the interface goes down/unregistered, mpls_netdev_event
 *          (cf. mpls_init.c) will change this opcode.
 *********************************************************************/

MPLS_IN_OPCODE_PROTOTYPE(mpls_in_op_set_rx)
{
	/* 
	 * Change the incoming net_device for the socket buffer
	 */
	(*skb)->dev = (struct net_device*)data;
	return MPLS_RESULT_SUCCESS;
}


/* 
 * Changes: 
 *	20040120 RCAS: The device must be MPLS enabled and its labelspace != -1
 */

MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_set_rx) 
{
	struct mpls_interface *mpls_if = NULL; 
	struct mpls_ilm       *pilm    = NULL; 
	struct net_device     *dev     = NULL;
	unsigned int if_index          = 0; /* Incoming If Index */

	MPLS_ENTER;
	*data = NULL;
	if (direction != MPLS_IN) {
		MPLS_DEBUG("SET_RX only valid for incoming labels\n");
		MPLS_EXIT;
		return -EINVAL;
	}

	pilm = _mpls_as_ilm(parent);
	/*
	 * Get a reference to the device given the interface index
	 */
	
	if_index = instr->mir_set_rx;
	dev = dev_get_by_index(&init_net, if_index);
	if (unlikely(!dev)) {
		MPLS_DEBUG("SET_RX if_index %d unknown\n", if_index);
		MPLS_EXIT;
		return -ESRCH;
	}

	/*
	 * Check Interface to see if its MPLS enabled
	 */
	mpls_if = mpls_get_if_info(if_index);

	if ( (!mpls_if) || (mpls_if->labelspace == -1)) {
		MPLS_DEBUG("SET_RX if_index %d MPLS disabled\n", if_index);
		dev_put (dev);
		MPLS_EXIT;
		return -ESRCH;
	}
	
	*data = (void*)dev;

	/* 
	 * Add to the device list of ILMs (list_in) 
	 * NOTE: we're still holding a ref to dev.
	 * 
	 */
	list_add(&pilm->dev_entry, &(mpls_if->list_in));
	MPLS_EXIT;
	return 0;
}

/* Get the ifIndex of the device and returns it */
MPLS_UNBUILD_OPCODE_PROTOTYPE(mpls_unbuild_opcode_set_rx)
{
	struct net_device *dev;

	MPLS_ENTER;
	dev = _mpls_as_netdev(data);
	instr->mir_set_rx = dev->ifindex;
	MPLS_EXIT;
	return 0;
}

MPLS_CLEAN_OPCODE_PROTOTYPE(mpls_clean_opcode_set_rx) 
{
	struct net_device *dev   = NULL;
	/* dev is already being held */
	dev = _mpls_as_netdev(data); 
	mpls_list_del_init(& _mpls_as_ilm(parent)->dev_entry);
	dev_put(dev);
}



/*********************************************************************
 * MPLS_OP_SET
 * DESC   : "Define the outgoing interface and next hop"
 * EXEC   : mpls_out_op_set
 * BUILD  : mpls_build_opcode_set
 * UNBUILD: mpls_unbuild_opcode_set
 * CLEAN  : mpls_clean_opcode_set
 * INPUT  : false 
 * OUTPUT : true 
 * DATA   : Reference to MPLS destination cache entry (struct mpls_dst*) 
 * LAST   : true 
 * 
 * Remark : If the interface goes down/unregistered, mpls_netdev_event
 *          (cf. mpls_init.c) will change this opcode.
 *********************************************************************/
 
MPLS_OUT_OPCODE_PROTOTYPE(mpls_out_op_set)
{
	struct mpls_dst *md = data;

	MPLS_ENTER;

	/* Release the current dst in the socket buffer */
	if (skb_dst(*skb)) {
		dst_release(skb_dst(*skb));
	}

	/*
	 * Update the dst field of the skbuffer in "real time" 
	 */
	dst_hold(&md->u.dst);
	skb_dst_set(*skb, &md->u.dst);
	

	/* don't hold the dev we place in skb->dev, the dst is already */
	/* holding it for us */

	(*skb)->dev = md->u.dst.dev;

	MPLS_EXIT;

	return MPLS_RESULT_SUCCESS;
}

/*
 * JLEU: Are there cases where we do not want to assign a labelspace (which
 * creates the mpls_if) and still originate MPLS traffic?
 */

MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_set) 
{
	struct mpls_interface *mpls_if = NULL; 
	struct mpls_nhlfe  *pnhlfe    = NULL; 
	struct net_device     *dev     = NULL;
	struct mpls_dst       *md      = NULL;
	unsigned int if_index          = 0; /* Outgoing interface index */

	MPLS_ENTER;

	*data = NULL;
	if (direction != MPLS_OUT) {
		MPLS_DEBUG("SET only valid for outgoing labels\n");
		MPLS_EXIT;
		return -EINVAL;
	}

	if_index = instr->mir_set.mni_if;
	dev = dev_get_by_index(&init_net, if_index);
	
	if (unlikely(!dev)) {
		MPLS_DEBUG("SET if_index %d unknown\n", if_index);
		MPLS_EXIT;
		return -ESRCH;
	}

	mpls_if = mpls_get_if_info(dev->ifindex);
	if (!mpls_if) {
		MPLS_DEBUG("SET not an MPLS interface %d unknown\n", if_index);
		MPLS_EXIT;
		return -ESRCH;
	}

	/* 
	 * This opcode will use the passed NHLFE 
	 */
	pnhlfe = _mpls_as_nhlfe(parent);
	WARN_ON(!pnhlfe);
	
	/* 
	 * NOTE: mpls_dst_alloc holds the dev,
	 * so release the hold from dev lookup
	 * mpls_dst_alloc calls dst_hold
	 */
	md = mpls_dst_alloc(dev, &instr->mir_set.mni_addr);
	dev_put(dev);

	if (unlikely(!md)) {
		MPLS_DEBUG("SET error building DST info\n");
		*data = NULL;
		MPLS_EXIT;
		return -ENOMEM;
	}


	/* 
	 * Update the NHLFE MTU according to the number of pushes. 
	 */
	pnhlfe->nhlfe_mtu = dev->mtu - (4 * (*num_push));
	pnhlfe->nhlfe_mtu_limit = pnhlfe->nhlfe_mtu;

	/* 
	 * Add to the device list of NHLFEs (list_out) 
	 * 
	 */
	list_add(&pnhlfe->dev_entry, &mpls_if->list_out);
	*data      = (void*)md;
	*last_able = 1;
	MPLS_EXIT;
	return 0;
}


MPLS_UNBUILD_OPCODE_PROTOTYPE(mpls_unbuild_opcode_set)
{
        struct mpls_dst *md;

        MPLS_ENTER;

	md = data;
        memcpy(&instr->mir_set.mni_addr, &md->md_nh, sizeof(struct sockaddr));
        instr->mir_set.mni_if = md->u.dst.dev->ifindex;

        MPLS_EXIT;

        return 0;
}



/*
 *	Clean tasks: 
 *	- release the mpls_dst (opcode data)
 *	- remove this nhlfe from the device's list.
 * 	JLEU: hold device so mpls_dst_release doesn't delete it 
 *	RCAS: Why do we need to hold the dev ? 
 */
MPLS_CLEAN_OPCODE_PROTOTYPE(mpls_clean_opcode_set) 
{
	struct mpls_dst   *mdst  = data;
	struct net_device *dev   = NULL;

	MPLS_ENTER;
	dev  = mdst->u.dst.dev;
	dev_hold(dev);
	mpls_dst_release (mdst);
	mpls_list_del_init (&_mpls_as_nhlfe(parent)->dev_entry);
	dev_put(dev);
	MPLS_EXIT;
}


/*********************************************************************
 * MPLS_OP_SET_TC
 * DESC   : "Define the socket buffer (IN/OUT) tc index" 
 * EXEC   : mpls_out_op_set_tc
 * BUILD  : mpls_build_opcode_set_tc
 * UNBUILD: mpls_unbuild_opcode_set_tc
 * CLEAN  : mpls_clean_opcode_generic 
 * INPUT  : true 
 * OUTPUT : true 
 * DATA   : TC index to apply to skb. (unsigned short *) 
 * LAST   : false 
 *********************************************************************/
#ifdef CONFIG_NET_SCHED
MPLS_OPCODE_PROTOTYPE(mpls_op_set_tc)
{
	unsigned short *tc = NULL;
	tc = data;
	(*skb)->tc_index = *tc;
	return MPLS_RESULT_SUCCESS;
}


MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_set_tc) 
{
	unsigned short *tc = NULL;

	*data = NULL;
	tc = kmalloc(sizeof(*tc),GFP_ATOMIC);
	if (unlikely(!tc)) {
		MPLS_DEBUG("SET_TC error building TC info\n");
		return -ENOMEM;
	}
	*tc   = instr->mir_set_tc;
	*data = (void*)tc;
	return 0;
}

MPLS_UNBUILD_OPCODE_PROTOTYPE(mpls_unbuild_opcode_set_tc)
{
	MPLS_ENTER;
	instr->mir_set_tc = *(unsigned short *)data;
	MPLS_EXIT;
	return 0;
}
#endif




/*********************************************************************
 * MPLS_OP_SET_DS
 * DESC   : "Changes the DS field of the IPv4/IPv6 packet"
 * EXEC   : mpls_in_op_set_ds
 * BUILD  : mpls_build_opcode_set_ds
 * UNBUILD: mpls_unbuild_opcode_set_ds
 * CLEAN  : mpls_clean_opcode_generic 
 * INPUT  : true 
 * OUTPUT : false 
 * DATA   : DS field (unsigned short *) 
 * LAST   : false 
 *********************************************************************/
#ifdef CONFIG_NET_SCHED

MPLS_IN_OPCODE_PROTOTYPE(mpls_in_op_set_ds)
{
	unsigned short *ds = data;

	if (!MPLSCB(*skb)->bos) {
		MPLS_DEBUG("SET_DS and not BOS\n");
		return MPLS_RESULT_DROP;
	}
	MPLSCB(*skb)->prot->change_dsfield(*skb, (*ds));
	return MPLS_RESULT_SUCCESS;
}


MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_set_ds) 
{
	unsigned char  *ds = NULL;
	*data = NULL;
	ds = kmalloc(sizeof(*ds),GFP_ATOMIC);
	if (unlikely(!ds)) {
		MPLS_DEBUG("SET_DS error building DS info\n");
		return -ENOMEM;
	}
	*ds = instr->mir_set_ds;
	if (*ds > 0x3f) {
		MPLS_DEBUG("SET_DS DS(%02x) too big\n",*ds);
		return -EINVAL;
	}
	*data = (void*)ds;
	return 0;
}

MPLS_UNBUILD_OPCODE_PROTOTYPE(mpls_unbuild_opcode_set_ds)
{
	MPLS_ENTER;
	instr->mir_set_ds = *(unsigned short *)data;
	MPLS_EXIT;
	return 0;
}
#endif



/*********************************************************************
 * MPLS_OP_SET_EXP
 * DESC   : "Changes the 3 EXP bits of the label entry"
 * EXEC   : mpls_op_set_exp
 * BUILD  : mpls_build_opcode_set_exp
 * UNBUILD: mpls_unbuild_opcode_set_exp
 * CLEAN  : mpls_clean_opcode_generic 
 * INPUT  : true 
 * OUTPUT : true 
 * DATA   : EXP value (binary 000-111) (unsigned char *) 
 * LAST   : false 
 *********************************************************************/

MPLS_OPCODE_PROTOTYPE(mpls_op_set_exp)
{
	unsigned char *exp = data;
	MPLSCB(*skb)->exp = *exp;
	return MPLS_RESULT_SUCCESS;
}


MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_set_exp) 
{
	unsigned char  *exp = NULL;
	*data = NULL;
	exp = kmalloc(sizeof(*exp),GFP_ATOMIC);
	if (unlikely(!exp)) {
		MPLS_DEBUG("SET_EXP error building EXP info\n");
		return -ENOMEM;
	}
	*exp = instr->mir_set_exp;
	if (*exp >= MPLS_EXP_NUM) {
		MPLS_DEBUG("SET_EXP EXP(%d) too big\n",*exp);
		kfree(exp);
		return -EINVAL;
	}
	*data = (void*)exp;
	return 0;
}

MPLS_UNBUILD_OPCODE_PROTOTYPE(mpls_unbuild_opcode_set_exp)
{
	MPLS_ENTER;
	instr->mir_set_exp = *(unsigned char *)data;
	MPLS_EXIT;
	return 0;
}



/*********************************************************************
 * MPLS_OP_EXP2TC
 * DESC   : "Changes the TC index of the socket buffer according to"
 *          "the EXP bits in label entry"
 * EXEC   : mpls_op_exp2tc
 * BUILD  : mpls_build_opcode_exp2tc
 * UNBUILD: mpls_unbuild_opcode_exp2tc
 * CLEAN  : mpls_clean_opcode_generic 
 * INPUT  : true 
 * OUTPUT : true 
 * DATA   : e2ti (struct mpls_exp2tcindex_info*) - No ILM/NHLFE are held. 
 * LAST   : false 
 *********************************************************************/

#ifdef CONFIG_NET_SCHED

MPLS_OPCODE_PROTOTYPE(mpls_op_exp2tc)
{
	struct mpls_exp2tcindex_info *e2ti = NULL;

	BUG_ON(!data);
	BUG_ON(!(*skb));
	e2ti = data;
	if (e2ti->e2t[MPLSCB(*skb)->exp & 0x7] != 0xffff) {
		(*skb)->tc_index = e2ti->e2t[MPLSCB(*skb)->exp & 0x7];
	}
	return MPLS_RESULT_SUCCESS;
}



MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_exp2tc) 
{
	struct mpls_exp2tcindex_info *e2ti = NULL;
	int j;

	*data = NULL;
	/*
	 * Allocate e2ti object 
	 */
	e2ti = kmalloc(sizeof(*e2ti),GFP_ATOMIC);
	if (unlikely(!e2ti)) {
		MPLS_DEBUG("EXP2TC error building TC info\n");
		return -ENOMEM;
	}
	/*
	 * Define (as per instruction) how to map EXP values
	 * to TC indexes
	 */
	for (j = 0;j<MPLS_EXP_NUM; j++) {
		e2ti->e2t[j] = instr->mir_exp2tc.e2t[j];
	}

	*data = (void*)e2ti;
	return 0;
}

MPLS_UNBUILD_OPCODE_PROTOTYPE(mpls_unbuild_opcode_exp2tc)
{
	struct mpls_exp2tcindex_info *e2ti = data;
	int j;

	MPLS_ENTER;

	for(j=0;j<MPLS_EXP_NUM;j++) {
		instr->mir_exp2tc.e2t[j] = e2ti->e2t[j];
	}

	MPLS_EXIT;
	return 0;
}
#endif






/*********************************************************************
 * MPLS_OP_EXP2DS
 * DESC   : "Changes the DS field of the IPv4/IPv6 packet according to"
 *          "the EXP bits in label entry"
 * EXEC   : mpls_op_exp2ds
 * BUILD  : mpls_build_opcode_exp2ds
 * UNBUILD: mpls_unbuild_opcode_exp2ds
 * CLEAN  : mpls_clean_opcode_generic 
 * INPUT  : true 
 * OUTPUT : false 
 * DATA   : e2di (struct mpls_exp2dsmark_info*) - No ILM/NHLFE are held. 
 * LAST   : false 
 *********************************************************************/
MPLS_IN_OPCODE_PROTOTYPE(mpls_in_op_exp2ds)
{
	struct mpls_exp2dsmark_info *e2di = data;

	if (e2di->e2d[MPLSCB(*skb)->exp & 0x7] == 0xff)
		return MPLS_RESULT_SUCCESS;

	MPLSCB(*skb)->prot->change_dsfield(*skb, e2di->e2d[MPLSCB(*skb)->exp & 0x7]);

	return MPLS_RESULT_SUCCESS;
}




MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_exp2ds) 
{
	struct mpls_exp2dsmark_info *e2di  = NULL;
	int j;

	*data = NULL;
	/*
	 * Allocate e2di object 
	 */
	e2di = kmalloc(sizeof(*e2di),GFP_ATOMIC);
	if (unlikely(!e2di)) {
		MPLS_DEBUG("error building DSMARK info\n");
		return -ENOMEM;
	}

	/*
	 * Define (as per instruction) how to map EXP values
	 * to DS fields. 
	 */
	for (j = 0; j<MPLS_EXP_NUM; j++) {
		e2di->e2d[j] = instr->mir_exp2ds.e2d[j];
	}
	*data = (void*)e2di;
	return 0;
}

MPLS_UNBUILD_OPCODE_PROTOTYPE(mpls_unbuild_opcode_exp2ds)
{
	struct mpls_exp2dsmark_info *e2di = data;
	int j;

	MPLS_ENTER;

	for(j=0;j<MPLS_EXP_NUM;j++) {
		instr->mir_exp2ds.e2d[j] = e2di->e2d[j];
	}

	MPLS_EXIT;
	return 0;
}


/*********************************************************************
 * MPLS_OP_TC2EXP
 * DESC   : "Changes the EXP bits of the topmost label entry according"
 *          "to the TC index in skb & mask"
 * EXEC   : mpls_op_tc2exp
 * BUILD  : mpls_build_opcode_tc2exp
 * UNBUILD: mpls_unbuild_opcode_tc2exp
 * CLEAN  : mpls_clean_opcode_generic 
 * INPUT  : false 
 * OUTPUT : true 
 * DATA   : t2ei (struct mpls_tcindex2exp_info*) - No ILM/NHLFE are held. 
 * LAST   : false 
 *********************************************************************/
#ifdef CONFIG_NET_SCHED

MPLS_OUT_OPCODE_PROTOTYPE(mpls_out_op_tc2exp)
{
	struct mpls_tcindex2exp_info *t2ei = data;
	unsigned short tc;

	tc = (*skb)->tc_index & t2ei->t2e_mask;
	if (t2ei->t2e[tc] != 0xFF) {
		MPLSCB(*skb)->exp = t2ei->t2e[tc];
	}
	return MPLS_RESULT_SUCCESS;
}



MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_tc2exp) 
{
	struct mpls_tcindex2exp_info *t2ei = NULL;
	int j;

	*data = NULL;
	/*
	 * Allocate t2ei object 
	 */
	t2ei = kmalloc(sizeof(*t2ei),GFP_ATOMIC);
	if (unlikely(!t2ei)) {
		MPLS_DEBUG("TC2EXP error building EXP info\n");
		return -ENOMEM;
	}
	
	/*
	 * Define (as per instruction) the mask to apply
	 */
	t2ei->t2e_mask = instr->mir_tc2exp.t2e_mask;
	if (t2ei->t2e_mask >= MPLS_TCINDEX_NUM) {
		MPLS_DEBUG("TC2EXP mask(%02x) too large\n", t2ei->t2e_mask);
		kfree (t2ei);
		return -EINVAL;
	}

	/*
	 * Define (as per instruction) how to map TC indexes
	 * to EXP bits 
	 */
	for (j = 0; j<MPLS_TCINDEX_NUM; j++) {
		t2ei->t2e[j] = instr->mir_tc2exp.t2e[j];
	}
	*data = (void*)t2ei;
	return 0;
}

MPLS_UNBUILD_OPCODE_PROTOTYPE(mpls_unbuild_opcode_tc2exp) 
{
	struct mpls_tcindex2exp_info *t2ei = data;
	int j;

	MPLS_ENTER;

	instr->mir_tc2exp.t2e_mask = t2ei->t2e_mask;

	for (j=0;j<MPLS_TCINDEX_NUM;j++) {
		instr->mir_tc2exp.t2e[j] = t2ei->t2e[j];
	}

	MPLS_EXIT;
	return 0;
}
#endif



/*********************************************************************
 * MPLS_OP_DS2EXP
 * DESC   : "Changes the EXP bits of the topmost label entry according"
 *          "to the DS field of the IPv4/IPv6 packet"
 * EXEC   : mpls_op_ds2exp
 * BUILD  : mpls_build_opcode_ds2exp
 * UNBUILD: mpls_unbuild_opcode_ds2exp
 * CLEAN  : mpls_clean_opcode_generic 
 * INPUT  : false 
 * OUTPUT : true 
 * DATA   : d2ei (struct mpls_dsmark2exp_info*) - No ILM/NHLFE are held. 
 * LAST   : false 
 *********************************************************************/
MPLS_OUT_OPCODE_PROTOTYPE(mpls_out_op_ds2exp)
{
	struct mpls_dsmark2exp_info *d2ei = data;
	unsigned char ds;

	ds = MPLSCB(*skb)->prot->get_dsfield(*skb);

	if (d2ei->d2e[ds] != 0xFF) {
		MPLSCB(*skb)->exp = d2ei->d2e[ds];
	}
	return MPLS_RESULT_SUCCESS;
}



MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_ds2exp) 
{
	struct mpls_dsmark2exp_info *d2ei  = NULL;
	int j;

	*data = NULL;
	/*
	 * Allocate d2ei object 
	 */
	d2ei = kmalloc(sizeof(*d2ei),GFP_ATOMIC);
	if (unlikely(!d2ei)) {
		MPLS_DEBUG("DS2EXP error building EXP info\n");
		return -ENOMEM;
	}

	/*
	 * Define (as per instruction) the mask to apply
	 */
	d2ei->d2e_mask = instr->mir_ds2exp.d2e_mask;
	if (d2ei->d2e_mask >= MPLS_DSMARK_NUM) {
		MPLS_DEBUG("DS2EXP mask(%02x) too large\n", d2ei->d2e_mask);
		kfree(d2ei);
		return -EINVAL;
	}

	/*
	 * Define (as per instruction) how to map DS marks 
	 * to EXP bits 
	 */
	for (j = 0; j<MPLS_DSMARK_NUM; j++) {
		d2ei->d2e[j] = instr->mir_ds2exp.d2e[j];
	}
	*data = (void*)d2ei;
	return 0;
}

MPLS_UNBUILD_OPCODE_PROTOTYPE(mpls_unbuild_opcode_ds2exp) 
{
	struct mpls_dsmark2exp_info *d2ei = data;
	int j;

	MPLS_ENTER;

	instr->mir_ds2exp.d2e_mask = d2ei->d2e_mask;

	for (j=0;j<MPLS_DSMARK_NUM;j++) {
		instr->mir_ds2exp.d2e[j] = d2ei->d2e[j];
	}

	MPLS_EXIT;
	return 0;
}





/*********************************************************************
 * MPLS_OP_NF2EXP
 * DESC   : "Changes the EXP bits of the topmost label entry according"
 *          "to the NF mark of the socket buffer". 
 * EXEC   : mpls_op_nf2exp
 * BUILD  : mpls_build_opcode_nf2exp
 * UNBUILD: mpls_build_opcode_nf2exp
 * CLEAN  : mpls_clean_opcode_generic 
 * INPUT  : false 
 * OUTPUT : true 
 * DATA   : n2ei (struct mpls_nfmark2exp_info*) - No ILM/NHLFE are held. 
 * LAST   : false 
 *********************************************************************/

#ifdef CONFIG_NETFILTER
MPLS_OUT_OPCODE_PROTOTYPE(mpls_out_op_nf2exp)
{
	struct mpls_nfmark2exp_info *n2ei = NULL;
	unsigned short nf = 0;

	BUG_ON(NULL == data);
	BUG_ON(NULL == *skb);
	n2ei = data;
	nf   = (*skb)->mark & n2ei->n2e_mask;
	if (n2ei->n2e[nf] != 0xFF) {
		MPLSCB(*skb)->exp = n2ei->n2e[nf];
	}

	return MPLS_RESULT_SUCCESS;
}


MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_nf2exp)
{
	struct mpls_nfmark2exp_info *n2ei  = NULL;
	int j;

	*data = NULL;
	/*
	 * Allocate d2ei object 
	 */
	n2ei = kmalloc(sizeof(*n2ei),GFP_ATOMIC);
	if(unlikely(!n2ei)) {
		MPLS_DEBUG("NF2EXP error building EXP info\n");
		return -ENOMEM;
	}

	/*
	 * Define (as per instruction) the mask to apply
	 */
	n2ei->n2e_mask = instr->mir_nf2exp.n2e_mask;
	if (n2ei->n2e_mask >= MPLS_NFMARK_NUM) {
		MPLS_DEBUG("NF2EXP mask(%02x) too large\n", n2ei->n2e_mask);
		kfree(n2ei);
		return -EINVAL;
	}

	/*
	 * Define (as per instruction) how to map NF marks 
	 * to EXP bits 
	 */
	for (j = 0; j<MPLS_NFMARK_NUM; j++) {
		n2ei->n2e[j] = instr->mir_nf2exp.n2e[j];
	}
	*data = (void*)n2ei;
	return 0;
}

MPLS_UNBUILD_OPCODE_PROTOTYPE(mpls_unbuild_opcode_nf2exp)
{
	struct mpls_nfmark2exp_info *n2ei = data;
	int j;

	MPLS_ENTER;

	instr->mir_nf2exp.n2e_mask = n2ei->n2e_mask;

	for(j=0;j<MPLS_NFMARK_NUM;j++) {
		instr->mir_nf2exp.n2e[j] = n2ei->n2e[j];
	}

	MPLS_EXIT;
	return 0;
}

#endif








/*********************************************************************
 * Main data type to hold metainformation on opcodes
 * IN      : Function pointer to execute in ILM object
 * OUT     : Function pointer to execute in NHLFE object
 * BUILD   : Function pointer to build the opcode 
 * CLEANUP : Function pointer to clean the opcode 
 * EXTRA   : Ready to transmit (SET)
 * MSG     : Human readable format
 *********************************************************************/

struct mpls_ops mpls_ops[MPLS_OP_MAX] = {
	[MPLS_OP_NOP] = {
		.in      = mpls_op_nop,
		.out     = mpls_op_nop,
		.build   = NULL,
		.unbuild = NULL,
		.cleanup = NULL,
		.extra   = 0,
		.msg     = "NOP",
	},
	[MPLS_OP_POP] = {
		.in      = mpls_in_op_pop,
		.out     = NULL,
		.build   = mpls_build_opcode_pop,
		.unbuild = NULL,
		.cleanup = NULL,
		.extra   = 0,
		.msg     = "POP",
	},
	[MPLS_OP_PEEK] = {
		.in      = mpls_in_op_peek,
		.out     = NULL,
		.build   = mpls_build_opcode_peek,
		.unbuild = NULL,
		.cleanup = NULL,
		.extra   = 0,
		.msg     = "PEEK",
	},
	[MPLS_OP_PUSH] = {
		.in      = mpls_op_push,
		.out     = mpls_op_push,
		.build   = mpls_build_opcode_push,
		.unbuild = mpls_unbuild_opcode_push,
		.cleanup = mpls_clean_opcode_push,
		.extra   = 0,
		.msg     = "PUSH",
	},
	[MPLS_OP_DLV] = {
		.in      = mpls_in_op_dlv,
		.out     = NULL,
		.build   = mpls_build_opcode_dlv,
		.unbuild = NULL,
		.cleanup = NULL,
		.extra   = 0,
		.msg     = "DLV",
	},
	[MPLS_OP_FWD] = {
		.in      = mpls_op_fwd,
		.out     = mpls_op_fwd,
		.build   = mpls_build_opcode_fwd,
		.unbuild = mpls_unbuild_opcode_fwd,
		.cleanup = mpls_clean_opcode_fwd,
		.extra   = 0,
		.msg     = "FWD",
	},
#ifdef CONFIG_NETFILTER
	[MPLS_OP_NF_FWD] = {
		.in      = NULL,
		.out     = mpls_out_op_nf_fwd,
		.build   = mpls_build_opcode_nf_fwd,
		.unbuild = mpls_unbuild_opcode_nf_fwd,
		.cleanup = mpls_clean_opcode_nf_fwd,
		.extra   = 0,
		.msg     = "NF_FWD",
	},
#endif
	[MPLS_OP_DS_FWD] = {
		.in      = NULL,
		.out     = mpls_out_op_ds_fwd,
		.build   = mpls_build_opcode_ds_fwd,
		.unbuild = mpls_unbuild_opcode_ds_fwd,
		.cleanup = mpls_clean_opcode_ds_fwd,
		.extra   = 0,
		.msg     = "DS_FWD",
	},
	[MPLS_OP_EXP_FWD] = {
		.in      = mpls_op_exp_fwd,
		.out     = mpls_op_exp_fwd,
		.build   = mpls_build_opcode_exp_fwd,
		.unbuild = mpls_unbuild_opcode_exp_fwd,
		.cleanup = mpls_clean_opcode_exp_fwd,
		.extra   = 0,
		.msg     = "EXP_FWD",
	},
	[MPLS_OP_SET_RX] = {
		.in      = mpls_in_op_set_rx,
		.out     = NULL,
		.build   = mpls_build_opcode_set_rx,
		.unbuild = mpls_unbuild_opcode_set_rx,
		.cleanup = mpls_clean_opcode_set_rx,
		.extra   = 0,
		.msg     = "SET_RX",
	},
	[MPLS_OP_SET] = {
		.in      = NULL,
		.out     = mpls_out_op_set,
		.build   = mpls_build_opcode_set,
		.unbuild = mpls_unbuild_opcode_set,
		.cleanup = mpls_clean_opcode_set,
		.extra   = 1,
		.msg     = "SET",
	},
#ifdef CONFIG_NET_SCHED
	[MPLS_OP_SET_TC] = {
		.in      = mpls_op_set_tc,
		.out     = mpls_op_set_tc,
		.build   = mpls_build_opcode_set_tc,
		.unbuild = mpls_unbuild_opcode_set_tc,
		.cleanup = mpls_clean_opcode_generic,
		.extra   = 0,
		.msg     = "SET_TC",
	},
	[MPLS_OP_SET_DS] = {
		.in      = mpls_in_op_set_ds,
		.out     = NULL,
		.build   = mpls_build_opcode_set_ds,
		.unbuild = mpls_unbuild_opcode_set_ds,
		.cleanup = mpls_clean_opcode_generic,
		.extra   = 0,
		.msg     = "SET_DS",
	},
#endif
	[MPLS_OP_SET_EXP] = {
		.in      = mpls_op_set_exp,
		.out     = mpls_op_set_exp,
		.build   = mpls_build_opcode_set_exp,
		.unbuild = mpls_unbuild_opcode_set_exp,
		.cleanup = mpls_clean_opcode_generic,
		.extra   = 0,
		.msg     = "SET_EXP",
	},
#ifdef CONFIG_NET_SCHED
	[MPLS_OP_EXP2TC] = {
		.in      = mpls_op_exp2tc,
		.out     = mpls_op_exp2tc,
		.build   = mpls_build_opcode_exp2tc,
		.unbuild = mpls_unbuild_opcode_exp2tc,
		.cleanup = mpls_clean_opcode_generic,
		.extra   = 0,
		.msg     = "EXP2TC",
	},
#endif
	[MPLS_OP_EXP2DS] = {
		.in      = mpls_in_op_exp2ds,
		.out     = NULL,
		.build   = mpls_build_opcode_exp2ds,
		.unbuild = mpls_unbuild_opcode_exp2ds,
		.cleanup = mpls_clean_opcode_generic,
		.extra   = 0,
		.msg     = "EXP2DS",
	},
#ifdef CONFIG_NET_SCHED
	[MPLS_OP_TC2EXP] = {
		.in      = NULL,
		.out     = mpls_out_op_tc2exp,
		.build   = mpls_build_opcode_tc2exp,
		.unbuild = mpls_unbuild_opcode_tc2exp,
		.cleanup = mpls_clean_opcode_generic,
		.extra   = 0,
		.msg     = "TC2EXP",
	},
#endif
	[MPLS_OP_DS2EXP] = {
		.in      = NULL,
		.out     = mpls_out_op_ds2exp,
		.build   = mpls_build_opcode_ds2exp,
		.unbuild = mpls_unbuild_opcode_ds2exp,
		.cleanup = mpls_clean_opcode_generic,
		.extra   = 0,
		.msg     = "DS2EXP",
	},
#ifdef CONFIG_NETFILTER
	[MPLS_OP_NF2EXP] = {
		.in      = NULL,
		.out     = mpls_out_op_nf2exp,
		.build   = mpls_build_opcode_nf2exp,
		.unbuild = mpls_unbuild_opcode_nf2exp,
		.cleanup = mpls_clean_opcode_generic,
		.extra   = 0,
		.msg     = "NF2EXP",
	},
#endif
};
