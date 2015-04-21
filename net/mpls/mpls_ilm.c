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
 * Changes
 * 20040117 RCAS
 *      - Changed RADIX_TREE(mpls_ilm_tree, GFP_ATOMIC) (since it's locked).
 * 20040115 RCAS
 *	- Removed old legacy ioctl code.
 * 20040127 RCAS
 *	- Dynamic allocation of instructions.
 ****************************************************************************/

#include <generated/autoconf.h>
#include <asm/uaccess.h>
#include <asm/errno.h>
#include <linux/netdevice.h>	
#include <linux/in.h>		/* must be before route.h */
#include <linux/ip.h>		/* must be before route.h */
#include <linux/inetdevice.h>	/* must be before route.h */
#include <net/route.h>
#include <net/mpls.h>
#include <linux/genetlink.h>
#include <linux/socket.h>
#include <net/net_namespace.h>

LIST_HEAD(mpls_ilm_list);

/* forward declarations */
static struct dst_entry *ilm_dst_check(struct dst_entry *dst, u32 cookie);
static void              ilm_dst_destroy(struct dst_entry *dst);
static struct dst_entry *ilm_dst_negative_advice(struct dst_entry *dst);
static void              ilm_dst_link_failure(struct sk_buff *skb);
static void              ilm_dst_update_pmtu(struct dst_entry *dst, u32 mtu);
static int               ilm_dst_gc(struct dst_ops *ops);

struct dst_ops ilm_dst_ops = {
	.family		 =  AF_MPLS,
	.protocol	 = __constant_htons(ETH_P_MPLS_UC),
	.gc		 = ilm_dst_gc,
	.check		 = ilm_dst_check,
	.destroy	 = ilm_dst_destroy,
	.negative_advice = ilm_dst_negative_advice,
	.link_failure	 = ilm_dst_link_failure,
	.update_pmtu	 = ilm_dst_update_pmtu,
	.entries	 = ATOMIC_INIT(0)
};

static struct dst_entry *
ilm_dst_check (struct dst_entry *dst, u32 cookie)
{
	MPLS_ENTER;
	dst_release(dst);
	MPLS_EXIT;
	return NULL;
}

/**
 *      ilm_dst_destroy - cleanup for a MPLS dst_entry
 *      @dst: 'this', object that is being destroyed.
 *
 *      The object ends life here. Perform the necessary
 *      clean up, but do not call dst_free(..) etc.
 **/

static void
ilm_dst_destroy (struct dst_entry *dst)
{
	MPLS_ENTER;
	MPLS_EXIT;
}

static struct dst_entry *
ilm_dst_negative_advice (struct dst_entry *dst)
{
	MPLS_ENTER;
	dst_release(dst);
	MPLS_EXIT;
	return NULL;
}

static void
ilm_dst_link_failure (struct sk_buff *skb)
{
	MPLS_ENTER;
	MPLS_EXIT;
}

static void
ilm_dst_update_pmtu (struct dst_entry *dst, u32 mtu)
{
	MPLS_ENTER;
	MPLS_EXIT;
}

static int
ilm_dst_gc (struct dst_ops *ops)
{
	MPLS_ENTER;
	MPLS_EXIT;
	return 0;
}

/**
 *      mpls_ilm_dst_alloc - construct a mpls_ilm entry.
 *
 **/

struct mpls_ilm*
mpls_ilm_dst_alloc(unsigned int key, struct mpls_label *ml,
	unsigned short family, struct mpls_instr_elem *instr, int instr_len)
{
	struct mpls_ilm *ilm;
	int result;

	MPLS_ENTER;

	ilm = dst_alloc (&ilm_dst_ops);
	if (unlikely(!ilm))
		goto ilm_dst_alloc_0;

	memcpy(&(ilm->ilm_label),ml,sizeof(struct mpls_label));
	INIT_LIST_HEAD(&ilm->dev_entry);
	INIT_LIST_HEAD(&ilm->nhlfe_entry);
	INIT_LIST_HEAD(&ilm->global);

	ilm->ilm_instr      = NULL;
	ilm->ilm_key        = key;
	ilm->ilm_labelspace = ml->ml_index;
	ilm->ilm_age        = jiffies;
	ilm->ilm_proto      = mpls_proto_find_by_family(family);
	ilm->ilm_fix_hh     = 0;
	if (unlikely(!ilm->ilm_proto)) {
		MPLS_DEBUG("Unable to find protocol driver for '0x%04x'\n",
			family);
		goto ilm_dst_alloc_1;
	} else {
		ilm->u.dst.input = ilm->ilm_proto->local_deliver;
	}
	ilm->u.dst.dev	    = init_net.loopback_dev;

	result = mpls_set_in_instrs(instr, instr_len, ilm);

	if (result)
		goto ilm_dst_alloc_2;

	MPLS_EXIT;
	return ilm;

/* Error Path */
ilm_dst_alloc_2:
	mpls_proto_release(ilm->ilm_proto);
ilm_dst_alloc_1:
	ilm->u.dst.obsolete = 1;
	dst_free(&ilm->u.dst);

ilm_dst_alloc_0:
	MPLS_EXIT;
	return NULL;
}


/*
 * MPLS info radix tree and corresponding lock
 */
RADIX_TREE(mpls_ilm_tree, GFP_ATOMIC);

DEFINE_SPINLOCK(mpls_ilm_lock);

/*
 * Some label values are reserved. 
 * For incoming label values of "IPv4 EXPLICIT NULL" and "IPv6 EXPLICIT NULL",
 * the instructions to execute are well defined. 
 */

/** 
 * ILM objects associated to reserved labels
 * RCAS: _IMPORTANT_ reserved labels *ARE NOT* in tree!
 **/

static struct mpls_reserved_labels {
	struct mpls_ilm *ilm;  /* Pointer to the ILM object              */ 
	char *msg;		   /* Description of the Label               */
	int bos;		   /* 1 -> it MUST be at the bottom of stack */
} mpls_reserved[16] = {
	{ NULL,                "IPv4 EXPLICIT NULL", 1 },
	{ NULL,                "ROUTER ALERT",       0 },
	{ NULL,                "IPv6 EXPLICIT NULL", 1 },
	{ NULL,                "IMPLICIT NULL",      1 },
	{ NULL,                "RESERVED",           0 },
	{ NULL,                "RESERVED",           0 },
	{ NULL,                "RESERVED",           0 },
	{ NULL,                "RESERVED",           0 },
	{ NULL,                "RESERVED",           0 },
	{ NULL,                "RESERVED",           0 },
	{ NULL,                "RESERVED",           0 },
	{ NULL,                "RESERVED",           0 },
	{ NULL,                "RESERVED",           0 },
	{ NULL,                "RESERVED",           0 },
	{ NULL,                "RESERVED",           0 },
	{ NULL,                "RESERVED",           0 }
};

/**
 *	mpls_insert_ilm - Inserts the given ILM object in the MPLS Input 
 *	Information Radix Tree using the given key.
 *	@key: key to use 
 *	@ilm: ilm object. 
 *	
 *	Returns 0 on success, or:
 *		-ENOMEM : unable to allocate node in the radix tree.
 **/

int 
mpls_insert_ilm (unsigned int key, struct mpls_ilm *ilm) 
{
	int retval = 0;

	mpls_ilm_hold (ilm);
	retval = radix_tree_insert (&mpls_ilm_tree, key, ilm);
	if (unlikely(retval)) {
		MPLS_DEBUG("Error create node with key %u in radix tree\n",key);
		retval = -ENOMEM;
	}
	list_add_rcu(&ilm->global, &mpls_ilm_list);
	return retval;
}

/**
 *	mpls_remove_ilm - Remove the node given the key from the MPLS Input 
 *	Information Radix Tree.
 *	@key : key to use 
 *
 *	This function deletes the ILM object from the Radix Tree, but please
 *	also note that the object is not freed, and that the caller is
 *	responsible for	decreasing the refcount if necessary.
 *
 *	Returns the node removed from the tree (which still needs to be
 *	released) or NULL if no such key/element exists in the tree.
 *	Caller must hold write lock
 *
 **/

struct mpls_ilm* 
mpls_remove_ilm (unsigned int key)
{
	struct mpls_ilm *ilm = NULL;

	MPLS_ENTER;
	ilm = radix_tree_delete (&mpls_ilm_tree, key);
	if (!ilm) {
		MPLS_DEBUG("node key %u not found.\n",key);
		return NULL;
	}

	list_del_rcu(&ilm->global);
	mpls_ilm_release (ilm);

	MPLS_EXIT;
	return ilm;
}

/**
 *	mpls_get_ilm - Get a reference to a ILM object. 
 *	@key : key to look for in the ILM Radix Tree. 
 *
 *	This function can be used to get a reference to a ILM object given a
 *	key.  *	Returns a pointer to the ILM object, NULL on error. 
 *
 *	Remark: this function increases the refcount of the ILM object,
 *	since it calls to mpls_ilm_hold. Caller is responsible to
 *	release the object when it is no longer needed (by using
 *	"mpls_ilm_release").
 **/

struct mpls_ilm* 
mpls_get_ilm (unsigned int key) 
{
	struct mpls_ilm *ilm = NULL;

	rcu_read_lock();
	ilm = radix_tree_lookup (&mpls_ilm_tree,key);
	smp_read_barrier_depends();
	if (likely(ilm))
		mpls_ilm_hold(ilm);

	rcu_read_unlock();
	return ilm;
}

/**
 *	mpls_get_ilm_by_label - Get a reference to a ILM given an incoming
 *	   label/labelspace.
 *	@label:      Incoming label from network core.
 *	@labelspace: Labelspace of the incoming interface.
 *	@bos:        Status of BOS for the current label being processed
 *
 *	Allows the caller to get a reference to the ILM object given the
 *	label value, and incoming interface/labelspace.
 *	Returns a pointer to the ILM object, NULL on error. 
 *	Remark1: This function increases the refcount of the ILM object, since 
 *		it calls "mpls_ilm_hold". Caller must release the object
 *		when it is no longer needed.
 *	Remark2: uses the function above.
 **/

struct mpls_ilm* 
mpls_get_ilm_by_label (struct mpls_label *label, int labelspace, char bos) 
{
	struct mpls_ilm *ilm = NULL;

	/* handle the reserved label range */
	if (label->ml_type == MPLS_LABEL_GEN && label->u.ml_gen < 16) {
		int want_bos = mpls_reserved[label->u.ml_gen].bos;
		MPLS_DEBUG("%s\n",mpls_reserved[label->u.ml_gen].msg);
		ilm = mpls_reserved[label->u.ml_gen].ilm;
		if (unlikely(!ilm)) {
			MPLS_DEBUG("invalid incoming label, dropping\n");
			return NULL;
		}
		mpls_ilm_hold(ilm);
		if ((want_bos && !bos) || (!want_bos && bos)) {
			mpls_ilm_release (ilm);
			MPLS_DEBUG("invalid incoming labelstack, dropping\n");
			return NULL;
		}
	} else {
		/* not reserved label */
		ilm = mpls_get_ilm (mpls_label2key(labelspace,label));
		if (unlikely(!ilm)) {
			MPLS_DEBUG("unknown incoming label, dropping\n");
			return NULL;
		}
	}
	return ilm;
}

/**
 *	mpls_destroy_in_instrs - Destroy ILM opcodes. 
 *	@ilm:	ILM object
 *
 *	This function completely destroys the instruction list for this 
 *	ILM object: it unregisters the opcodes from sysfs. When the 
 *      refcnt of the instr reaches zero (a file may be opened) they 
 *      will be freed.
 *
 *	ilm_instr is set to NULL.
 **/

void
mpls_destroy_in_instrs (struct mpls_ilm *ilm) 
{
	MPLS_ENTER;
	mpls_instrs_free (ilm->ilm_instr);
	ilm->ilm_instr = NULL;
	MPLS_EXIT;
}

/**
 * 	mpls_set_in_instrs - Set Instruction list for this ILM. 
 *	@mie:   Array of instruction elements set by user 
 *	@lenth: Array lenght. Number of valid entries
 *	@ilm:	The ILM object ('this')
 *
 *	Return 0 on success. Called in process context only and m
 *	ay sleep
 **/
int
mpls_set_in_instrs ( struct mpls_instr_elem *mie, int length,
	struct mpls_ilm *ilm) 
{
	/* To store (tmp) the linked list of instr. */
	struct mpls_instr *instr_list = NULL;
	
	/* Build temporary opcode set from mie */
	if (!mpls_instrs_build(mie, &instr_list, length, MPLS_IN, ilm))
		return -1;

	/* Commit the new ones */
	if (ilm->ilm_instr)
		mpls_instrs_free(ilm->ilm_instr);
	ilm->ilm_instr = instr_list;

	return 0;
}




/**
 *	mpls_set_in_label_instrs - define the incoming opcode set. 
 *	@mir: request.
 *
 *	Updates the ILM object corresponding to the label/labelspace
 *	in the request, by changing the instrs as given.
 *
 *	Returns 0 on success, or
 *	   -ENXIO
 *	   -ESRCH
 *	   -EEXIST
 *	   -1
 **/

int 
mpls_set_in_label_instrs (struct mpls_instr_req *mir) 
{
	int labelspace           =  mir->mir_index;
	struct mpls_label *ml    = &mir->mir_label;
	unsigned int key         = mpls_label2key (labelspace,ml);
	struct mpls_ilm *ilm = mpls_get_ilm(key);
	int ret;

	if (unlikely(!ilm))
		return -ESRCH;

	ret = mpls_set_in_instrs (mir->mir_instr,mir->mir_instr_length, ilm); 
	mpls_ilm_release(ilm);
	return ret;
}

/**
 *	mpls_set_in_label_proto - change the proto driver on a ilm
 *	@mil: request.
 *
 *	Updates the ILM object corresponding to the label/labelspace
 *	in the request, by changing the proto driver as given.
 *
 *	Returns 0 on success or no change, or
 *	   -ESRCH
 *	   -EINVAL
 */
int 
mpls_set_in_label_proto (struct mpls_in_label_req *mil)
{
	unsigned int key = mpls_label2key(mil->mil_label.ml_index,
		&mil->mil_label);
	struct mpls_ilm *ilm = mpls_get_ilm(key);
	int retval = 0;
	if (!ilm) {
		retval = -ESRCH;
		goto err_no_ilm;
	}

	if (ilm->ilm_proto->family != mil->mil_proto) {
		struct mpls_prot_driver *prot =
			mpls_proto_find_by_family(mil->mil_proto);
		if (!prot) {
			retval = -EINVAL;
			goto err_no_prot;
		}
		if (ilm->ilm_proto)
			mpls_proto_release(ilm->ilm_proto);
		ilm->ilm_proto = prot;
		ilm->u.dst.input = prot->local_deliver;
	}

err_no_prot:
	mpls_ilm_release (ilm);
err_no_ilm:
	return retval;
}

/**
 *	mpls_is_reserved_label - return 1 if label is reserved.
 *	@label - label to check.
 **/

static inline int 
mpls_is_reserved_label (const struct mpls_label *label)
{
	BUG_ON(!label);
	if (unlikely((label->ml_type == MPLS_LABEL_GEN) &&
		     (label->u.ml_gen > MPLS_IPV6_EXPLICIT_NULL) &&
		     (label->u.ml_gen < 16))) {
		return 1;
	}
	return 0;
}




/**
 *	mpls_add_in_label - Add a label to the incoming tree.
 *	@in : mpls_in_label_req
 *
 *	Process context entry point to add an entry (ILM) in the incoming label 
 *	map database. It adds new corresponding node to the Incoming Radix Tree.
 *	It sets the ILM object reference count to 1, the ilm age to jiffies, the
 *	protocol to IPv4, the default instruction set (POP,PEEK) and initializes
 *	both the dev_entry and nhlfe_entry lists. The node's key is set to the 
 *	mapped	key from the label/labelspace in the request.
 *
 *	Returns 0 on success, or else.
 *
 *	Changes 
 *	20031125 : RCAS 
 *		o Verify that no node exists for the tree before alloc'ing 
 *		  the ILM, so we can get out earlier in case we fail.
 *	20041020 : JLEU
 *		o Removed mpls_set_default_in_instrs()
 **/

int 
mpls_add_in_label (const struct mpls_in_label_req *in) 
{
	struct mpls_ilm *ilm     = NULL; /* New ILM to insert */
	struct mpls_label *ml    = NULL; /* Requested Label */
	unsigned int key         = 0;    /* Key to use */
	int retval               = 0;
	struct mpls_instr_elem instr[2];

	MPLS_ENTER;

	BUG_ON(!in);
	ml = (struct mpls_label *)&in->mil_label;

	if (mpls_is_reserved_label(ml)) {
		MPLS_DEBUG("Unable to add reserved label to ILM\n");
		retval = -EINVAL;
		goto error;
	}

	/* Obtain key */
	key = mpls_label2key(/* labelspace*/ ml->ml_index, ml);

	/* Check if the node already exists */ 
	ilm = mpls_get_ilm(key);
	if (unlikely(ilm)) {
		printk (MPLS_ERR "MPLS: node %u already exists\n",key);
		mpls_ilm_release(ilm);  
		retval = -EEXIST;
		goto error;
	} 

	/*
	 * Allocate a new input Information/Label,
	 */

	instr[0].mir_direction = MPLS_IN;
	instr[0].mir_opcode    = MPLS_OP_POP;
	instr[1].mir_direction = MPLS_IN;
	instr[1].mir_opcode    = MPLS_OP_PEEK;

	ilm = mpls_ilm_dst_alloc (key, ml, in->mil_proto, instr, 2);
	if (unlikely(!ilm)) {
		retval = -ENOMEM;
		goto error;
	}

	/* Insert into ILM tree */
	spin_lock_bh (&mpls_ilm_lock);
	if (unlikely(mpls_insert_ilm(key,ilm))) {
		mpls_ilm_release (ilm);
		spin_unlock_bh (&mpls_ilm_lock);

		ilm->u.dst.obsolete = 1;
		dst_free (&ilm->u.dst);
		retval = -ENOMEM;
		goto error;
	}

	mpls_ilm_hold(ilm);
	spin_unlock_bh (&mpls_ilm_lock);

	/* we have hold a refcnt to the ilm across mpls_ilm_event()
	 * to make sure it can't disappear
	 */
	mpls_ilm_event(MPLS_CMD_NEWILM, ilm);
	mpls_ilm_release(ilm);

error:
	MPLS_EXIT;
	return retval;
}

/**
 *	__mpls_del_in_label - send delete event and schedule ILM for freeing
 *	@in : mpls_ilm
 *
 *	This function does the work of actually 'free'ing a ILM datastructure.
 *	It first send a event notifing userland that the ILM is going a way,
 *	then delete the instructions removed reference to the proto driver,
 *	then finally schedules the ILM for freeing.
 *
 *	This functions much be called holding a reference to the ILM,
 *	At this point it is the ONLY reference to the ILM (it should have
 *	been removed from the tree or the array) When this functions exits
 *	ilm is nolonger valid ...
 **/
void __mpls_del_in_label(struct mpls_ilm *ilm) {
	/* we're still holding a ref to the ilm, so it is safe to
	 * call mpls_ilm_event
	 */
	mpls_ilm_event(MPLS_CMD_DELILM, ilm);

	/* remove the instructions from the ILM, so ass to release
	 * our references to NHLFEs
	 */
	mpls_destroy_in_instrs (ilm);
        mpls_proto_release(ilm->ilm_proto);
	ilm->ilm_proto = NULL;

	/* release the refcnt we aquired in mpls_get_ilm() */
	mpls_ilm_release (ilm);

	/* tell the dst system this one is ready for removal */
	ilm->u.dst.obsolete = 1;
	call_rcu(&ilm->u.dst.rcu_head, dst_rcu_free);
}

/**
 *	mpls_del_in_label - Del a label from the incoming tree (ILM)
 *	@in : mpls_in_label_req
 *
 *	User context entry point, this function removes an incoming label
 *	from the incoming radix tree (that is, from the ILM). It constructs
 *	the associated key from the label/labelspace in the request, and 
 *	updates the passed struct with the ILM information. 
 **/

int 
mpls_del_in_label(struct mpls_in_label_req *in) 
{
	struct mpls_ilm *ilm = NULL;
	struct mpls_label   *ml  = NULL; 
	unsigned int key         = 0;

	MPLS_ENTER;
	BUG_ON(!in);
	ml  = &in->mil_label;
	key = mpls_label2key(/* labelspace*/ ml->ml_index, ml);

	ilm = mpls_get_ilm(key);
	if (unlikely(!ilm)) {
		MPLS_DEBUG("Node %u was not in tree\n",key);
		MPLS_EXIT;
		return  -ESRCH;
	}

	spin_lock_bh (&mpls_ilm_lock);

	if (atomic_read(&ilm->u.dst.__refcnt) != 2) {
		/* someone else is hold a refcnt, we can't delete */

		/* release the refcnt we aquired in mpls_get_ilm() */
		mpls_ilm_release (ilm);
		spin_unlock_bh (&mpls_ilm_lock);

		MPLS_DEBUG("Node %u is being used\n",key);
		MPLS_EXIT;
		return -EBUSY;
        }

	/*
	 * Remove a ILM from the tree
	 */
	ilm = mpls_remove_ilm(key);

	spin_unlock_bh (&mpls_ilm_lock);

	if (unlikely(!ilm)) {
		MPLS_DEBUG("Node %u was not in tree\n",key);
		MPLS_EXIT;
		return  -ESRCH;
	}

	__mpls_del_in_label(ilm);

	MPLS_EXIT;
	return 0; 
}

/**
 *	mpls_attach_in2out - Establish a xconnect between a ILM and a NHLFE.
 *	@req : crossconnect request. 
 *
 *	Establishes a "cross-connect", a forwarding entry. The incoming label
 *	is swapped to the outgoing one. Given the incoming label and label
 *	space 
 *
 *	(req), this function updates the ILM object so we change the last instr 
 *	from DLV/PEEK to FWD, whose opcode data is a held ref. to the new NHLFE 
 *	(as given by the key in req).
 *	Returns 0 on success. Process context only.
 *
 *	Remarks:
 *	    o Be careful when  detroying the NHLFE  object (you should dettach
 *	      the xconnect in order to release the NHLFE)
 *
 *	Changes:
 *	o 20040120 RCAS: Removed kfree((unsigned short*)mi->mi_data);
 *	               for DLV (data in DLV opcode is NULL).
 *	o 20040127 RCAS: Instruction Linked list.	
 **/

int 
mpls_attach_in2out(struct mpls_xconnect_req *req) 
{
	struct mpls_instr       *mi  = NULL; 
	struct mpls_nhlfe    *nhlfe = NULL;
	struct mpls_ilm     *ilm = NULL;
	unsigned short op = 0;
	int  labelspace, key;

	MPLS_ENTER;
	labelspace = req->mx_in.ml_index;

	/* Hold a ref to the ILM */
	key = mpls_label2key(labelspace,&(req->mx_in));
	ilm = mpls_get_ilm(key);
	if (unlikely(!ilm))  {
		MPLS_DEBUG("Node %u does not exist in radix tree\n",key);
		MPLS_EXIT;
		return -ESRCH;
	}

	/* Hold a ref to the NHLFE */
	key = mpls_label2key(0,&(req->mx_out));
	nhlfe = mpls_get_nhlfe(key);
	if (unlikely(!nhlfe)) {
		MPLS_DEBUG("Node %u does not exist in radix tree\n",key);
		mpls_ilm_release(ilm);
		MPLS_EXIT;
		return -ESRCH;
	}

	if (unlikely(!ilm->ilm_instr)) {
		MPLS_DEBUG("No instruction Set!")
		mpls_ilm_release(ilm);
		mpls_nhlfe_release(nhlfe);
		MPLS_EXIT;
		return -ESRCH;
	}



	/*
	 * Update the instructions: now, instead of "DLV"/"PEEK", now
	 * we "FWD". The NHLFE is not released (is held by the opcode). 
	 */

	/* Lookup the last instr */
	for (mi = ilm->ilm_instr; mi->mi_next;mi = mi->mi_next); /* nop*/

	op = mi->mi_opcode;

	switch (op) {
		case MPLS_OP_DLV:
			mi->mi_opcode = MPLS_OP_FWD;
			mi->mi_data   = (void*)nhlfe;
			break;
		case MPLS_OP_FWD:
			mpls_xc_event(MPLS_CMD_DELXC, ilm,
				_mpls_as_nhlfe(mi->mi_data));
			mpls_nhlfe_release(_mpls_as_nhlfe(mi->mi_data));
			mi->mi_data   = (void*)nhlfe;
			break;
		case MPLS_OP_PEEK:
			mi->mi_opcode = MPLS_OP_FWD;
			mi->mi_data   = (void*)nhlfe;
			break;
	}
	mpls_xc_event(MPLS_CMD_NEWXC, ilm, nhlfe);
	mpls_ilm_release(ilm);
	return 0; 
}




/**
 *	mpls_dettach_in2out - Dettach a xconnect between a ILM and a NHLFE.
 *	@req : crossconnect request. 
 *
 *	Dettaches a "cross-connect", a forwarding entry. Checks if the latest 
 *	instruction is a FWD and updates it to a PEEK. Releases the
 *	corresponding NHLFE (cf. mpls_attach_in2out).
 *
 *	Returns 0 on success. Process context only.
 **/

int 
mpls_detach_in2out(struct mpls_xconnect_req *req) 
{
	struct mpls_instr       *mi  = NULL;
	struct mpls_nhlfe    *nhlfe = NULL;
	struct mpls_ilm     *ilm = NULL;
	unsigned int     key = 0;
	int labelspace;
	int ret = 0;

	MPLS_ENTER;
	BUG_ON(!req);

	/* Hold a ref to the ILM, The 'in' segment */ 
	labelspace = req->mx_in.ml_index;
	key        = mpls_label2key(labelspace,&(req->mx_in));
	ilm = mpls_get_ilm(key);
	if (unlikely(!ilm)) {
		MPLS_DEBUG("Node %u does not exist in radix tree\n",key);
		ret = -ESRCH;
		goto err_no_ilm;
	}

	/* Check that there is an instruction set! */
	if (unlikely(!ilm->ilm_instr)) {
		MPLS_DEBUG("No instruction Set!")
		ret = -ESRCH;
		goto err_no_ilm_instr;
	}


	/* Fetch the last instr, make sure it is FWD*/
	for (mi = ilm->ilm_instr; mi->mi_next;mi = mi->mi_next); /* nop*/

	if (!mi   ||   mi->mi_opcode != MPLS_OP_FWD) {
		MPLS_DEBUG("opcode not found!\n");
		ret = -ENXIO;
		goto err_no_fwd;
	}

	/* Get the current held nhlfe for the last in instr */
	nhlfe = mi->mi_data;
	key = mpls_label2key(0,&(req->mx_out));

	/* Make sure it is the good nhlfe */
	if (!nhlfe ||  key != nhlfe->nhlfe_key) {
		/* Do not release the NHLFE, it was invalid */ 
		MPLS_DEBUG("Invalid NHLFE  %u\n",key);
		ret = -ENXIO;
		goto err_no_nhlfe;
	}

	/* The new last opcode for this ILM is now peek */
	mi->mi_opcode = MPLS_OP_PEEK;
	/* With no data */
	mi->mi_data   = NULL; 

	/* Release the NHLFE held by the Opcode (cf. mpls_attach_in2out) */

	mpls_xc_event(MPLS_CMD_DELXC, ilm, nhlfe);
	mpls_nhlfe_release(nhlfe); 
	ret = 0;
err_no_nhlfe:
err_no_fwd:
	/* Release the ILM after use */
	mpls_ilm_release(ilm);
err_no_ilm_instr:
err_no_ilm:
	MPLS_EXIT;
	return ret;
}

/**
 * 	mpls_init_reserved_label - Add an ILM object for a reserved label
 *	@label - reserved generic label value
 *	@ilm - ILM object to used for reserved label
 *
 *	Returns 0 on success
 **/

int 
mpls_add_reserved_label (int label, struct mpls_ilm* ilm)
{
	BUG_ON(label < 0 || label > 15);

	if (mpls_reserved[label].ilm)
		return -EEXIST;

	mpls_ilm_hold(ilm);
	mpls_reserved[label].ilm = ilm;

	return 0;
}

/**
 * 	mpls_del_reserved_label - remove the ILM object for a reserved label
 *	@label - reserved generic label value
 *
 *	Return the ILM object for the user to release
 *
 **/

struct mpls_ilm*
mpls_del_reserved_label (int label)
{
	struct mpls_ilm* ilm;
	BUG_ON(label < 0 || label > 15);

	ilm = mpls_reserved[label].ilm;
	mpls_reserved[label].ilm = NULL;
	return ilm;
}

int __init mpls_ilm_init(void)
{
	ilm_dst_ops.kmem_cachep =
		kmem_cache_create("ilm_dst_cache", sizeof(struct mpls_ilm), 0,
				  SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL);
                                                                                
	if (!ilm_dst_ops.kmem_cachep) {
		printk(MPLS_ERR "MPLS: failed to alloc ilm_dst_cache\n");
		return -ENOMEM;
	}
	return 0;
}

void __exit mpls_ilm_exit(void)
{
	if (ilm_dst_ops.kmem_cachep)
	    kmem_cache_destroy(ilm_dst_ops.kmem_cachep);
	return;
}

EXPORT_SYMBOL(__mpls_del_in_label);
EXPORT_SYMBOL(mpls_ilm_dst_alloc);
EXPORT_SYMBOL(mpls_add_reserved_label);
EXPORT_SYMBOL(mpls_del_reserved_label);
