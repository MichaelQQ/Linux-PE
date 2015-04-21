--- mpls-linux-2.6.35.y/net/mpls/mpls_nhlfe.c	1970-01-01 08:00:00.000000000 +0800
+++ linux-2.6.35-vpls/net/mpls/mpls_nhlfe.c	2015-04-20 20:24:43.759583630 +0800
@@ -0,0 +1,618 @@
+/*****************************************************************************
+ * MPLS
+ *      An implementation of the MPLS (MultiProtocol Label
+ *      Switching Architecture) for Linux.
+ *
+ * Authors:
+ *	  James Leu	<jleu@mindspring.com>
+ *	  Ramon Casellas   <casellas@infres.enst.fr>
+ *
+ *   (c) 1999-2004   James Leu	<jleu@mindspring.com>
+ *   (c) 2003-2004   Ramon Casellas   <casellas@infres.enst.fr>
+ *
+ *
+ *	      It implements:
+ *	      -add/get/del/flush for the out label tree
+ *	      -binding of FEC to out label
+ *
+ *      This program is free software; you can redistribute it and/or
+ *      modify it under the terms of the GNU General Public License
+ *      as published by the Free Software Foundation; either version
+ *      2 of the License, or (at your option) any later version.
+ *
+ * Changes:
+ *	20040102 RCAS: Commented, and clean up. 
+ *		- nhlfe_list lacks proper management. This list
+ *		should be updated when a NHLFE object is deleted. 
+ *		A possible approach would be to modify nhlfe_release.
+ *
+ ****************************************************************************/
+
+#include <generated/autoconf.h>
+#include <net/mpls.h>
+#include <asm/uaccess.h>
+#include <asm/atomic.h>
+#include <net/dst.h>
+#include <linux/rtnetlink.h>
+#include <linux/in.h>		/* must be before route.h */
+#include <linux/ip.h>		/* must be before route.h */
+#include <linux/inetdevice.h>	/* must be before route.h */
+#include <net/route.h>		/* must be before ip_fib.h */
+#include <net/ip_fib.h>
+#include <linux/genetlink.h>
+#include <net/net_namespace.h>
+
+LIST_HEAD(mpls_nhlfe_list);
+
+/* forward declarations */
+static struct dst_entry *nhlfe_dst_check(struct dst_entry *dst, u32 cookie);
+static void              nhlfe_dst_destroy(struct dst_entry *dst);
+static struct dst_entry *nhlfe_dst_negative_advice(struct dst_entry *dst);
+static void              nhlfe_dst_link_failure(struct sk_buff *skb);
+static void              nhlfe_dst_update_pmtu(struct dst_entry *dst, u32 mtu);
+static int               nhlfe_dst_gc(struct dst_ops *ops);
+
+struct dst_ops nhlfe_dst_ops = {
+	.family		 =  AF_MPLS,
+	.protocol	 = __constant_htons(ETH_P_MPLS_UC),
+	.gc		 = nhlfe_dst_gc,
+	.check		 = nhlfe_dst_check,
+	.destroy	 = nhlfe_dst_destroy,
+	.negative_advice = nhlfe_dst_negative_advice,
+	.link_failure	 = nhlfe_dst_link_failure,
+	.update_pmtu	 = nhlfe_dst_update_pmtu,
+	.entries	 = ATOMIC_INIT(0)
+};
+
+static struct dst_entry *
+nhlfe_dst_check (struct dst_entry *dst, u32 cookie)
+{
+	MPLS_ENTER;
+	dst_release(dst);
+	MPLS_EXIT;
+	return NULL;
+}
+
+/**
+ *      nhlfe_dst_destroy - cleanup for a MPLS dst_entry
+ *      @dst: 'this', object that is being destroyed.
+ *
+ *      The object ends life here. Perform the necessary
+ *      clean up, but do not call dst_free(..) etc.
+ **/
+
+static void
+nhlfe_dst_destroy (struct dst_entry *dst)
+{
+	MPLS_ENTER;
+	MPLS_EXIT;
+}
+
+static struct dst_entry *
+nhlfe_dst_negative_advice (struct dst_entry *dst)
+{
+	MPLS_ENTER;
+	dst_release(dst);
+	MPLS_EXIT;
+	return NULL;
+}
+
+static void
+nhlfe_dst_link_failure (struct sk_buff *skb)
+{
+	MPLS_ENTER;
+	MPLS_EXIT;
+}
+
+static void
+nhlfe_dst_update_pmtu (struct dst_entry *dst, u32 mtu)
+{
+	MPLS_ENTER;
+	MPLS_EXIT;
+}
+
+static int
+nhlfe_dst_gc (struct dst_ops *ops)
+{
+	MPLS_ENTER;
+	MPLS_EXIT;
+	return 0;
+}
+
+/**
+ *      nhlfe_dst_alloc - construct a mpls_nhlfe entry.
+ *
+ **/
+
+struct mpls_nhlfe*
+nhlfe_dst_alloc(unsigned int key)
+{
+	struct mpls_nhlfe *nhlfe;
+
+	MPLS_ENTER;
+
+	nhlfe = dst_alloc (&nhlfe_dst_ops);
+	if (unlikely(!nhlfe))
+		goto nhlfe_dst_alloc_0;
+
+	nhlfe->u.dst.dev	= init_net.loopback_dev;
+	nhlfe->u.dst.input	= mpls_switch;
+	nhlfe->u.dst.output	= mpls_output;
+
+	INIT_LIST_HEAD(&nhlfe->list_out);
+	INIT_LIST_HEAD(&nhlfe->list_in);
+	INIT_LIST_HEAD(&nhlfe->nhlfe_entry);
+	INIT_LIST_HEAD(&nhlfe->dev_entry);
+	INIT_LIST_HEAD(&nhlfe->global);
+
+	nhlfe->nhlfe_instr		= NULL;
+	nhlfe->nhlfe_propagate_ttl	= 1;
+	nhlfe->nhlfe_age		= jiffies;
+	nhlfe->nhlfe_key		= key;
+
+	MPLS_EXIT;
+	return nhlfe;
+
+/* Error Path */
+nhlfe_dst_alloc_0:
+	MPLS_EXIT;
+	return NULL;
+}
+
+
+/**
+ * mpls_nhlfe_tree: Radix Tree to hold NHLFE objects
+ **/
+RADIX_TREE(mpls_nhlfe_tree,GFP_ATOMIC);
+
+/**
+ * mpls_nhlfe_lock: lock for tree access.
+ **/
+DEFINE_SPINLOCK(mpls_nhlfe_lock);
+
+
+/**
+ * mpls_insert_nhlfe - Inserts the given NHLFE object in the MPLS
+ *   Output Information Radix Tree using the given key.
+ * @key : key to use
+ * @nhlfe : nhlfe object.
+ *
+ * Returns 0 on success, or:
+ *     -ENOMEM : unable to allocate node in the radix tree.
+ *
+ * Caller must hold mpls_nhlfe_lock
+ *
+ **/
+
+int 
+mpls_insert_nhlfe (unsigned int key, struct mpls_nhlfe *nhlfe) 
+{
+	int retval = 0;
+	retval = radix_tree_insert (&mpls_nhlfe_tree, key, nhlfe);
+	if (unlikely(retval))
+		retval = -ENOMEM;
+
+	list_add_rcu(&nhlfe->global, &mpls_nhlfe_list);
+
+	/* hold it for being in the tree */
+	mpls_nhlfe_hold (nhlfe);
+	return retval;
+}
+
+
+/**
+ *	mpls_remove_nhlfe - Remove the node given the key from the MPLS
+ *	Output Information Radix Tree.
+ *	@key : key to use
+ *
+ *	Must be called while holding a write lock on mpls_nhlfe_lock
+ *
+ *	This function deletes the NHLFE object from the Radix Tree, but please
+ *	also note that the object is not freed, and that the caller is
+ *	responsible for	decreasing the refcount if necessary.
+ *
+ *	Returns the node removed from the tree (which still needs to be
+ *	released) or NULL if no such key/element exists in the tree.
+ *
+ **/
+
+struct mpls_nhlfe* 
+mpls_remove_nhlfe (unsigned int key)
+{
+	struct mpls_nhlfe *nhlfe = NULL;
+
+	MPLS_ENTER;
+
+	nhlfe = radix_tree_delete(&mpls_nhlfe_tree, key);
+	if (!nhlfe)
+		MPLS_DEBUG("NHLFE node with key %u not found.\n",key);
+
+	list_del_rcu(&nhlfe->global);
+
+	/* release the refcnt for the tree hold it */
+	mpls_nhlfe_release (nhlfe);
+
+	MPLS_EXIT;
+	return nhlfe;
+}
+
+
+/**
+ *	mpls_get_nhlfe - Get a reference to a NHLFE object.
+ *	@key : key to look for in the NHLFE Radix Tree.
+ *
+ *	This function can be used to get a reference to a NHLFE object
+ *	given a key.
+ *	Returns a pointer to the NHLFE object, NULL on error.
+ *
+ *	Remark: this function increases the refcount of the NHLFE object, since it
+ *	calls to mpls_nhlfe_hold. Caller is responsible to release the object
+ *	when it is no longer needed (by using "mpls_nhlfe_release").
+ **/
+
+struct mpls_nhlfe*  
+mpls_get_nhlfe (unsigned int key) 
+{
+	struct mpls_nhlfe *nhlfe = NULL;
+
+	rcu_read_lock();
+	nhlfe = radix_tree_lookup (&mpls_nhlfe_tree, key);
+	smp_read_barrier_depends();
+	if (likely(nhlfe)) {
+		mpls_nhlfe_hold(nhlfe);
+	}
+	rcu_read_unlock();
+
+	return nhlfe;
+}
+
+/**
+ *	mpls_get_out_key - generate a key for out tree.
+ *
+ *	Returns an unused unique key to insert a NHLFE in the output
+ *	radix tree. 0 is not allowed (has special semantics).
+ *	Called in User context.
+ **/
+ 
+unsigned int 
+mpls_get_out_key(void) 
+{
+	static int new_key = 1;
+	struct mpls_nhlfe* dummy = NULL;
+
+	rcu_read_lock();
+	for (;;) {
+		if (++new_key <= 0)
+			new_key = 1;
+		dummy = radix_tree_lookup (&mpls_nhlfe_tree, new_key);
+		if (!dummy)
+			goto out;	
+	}
+out:
+	rcu_read_unlock();
+	return new_key;
+}
+
+/**
+ *	mpls_destroy_out_instrs - Destroy NHLFE instruction list. 
+ *	@nhlfe:	NHLFE object
+ *
+ *      This function completely destroys the instruction list for this
+ *      NHLFE object.
+ *
+ *      nhlfe_instr is set to NULL.
+ **/
+
+void
+mpls_destroy_out_instrs (struct mpls_nhlfe *nhlfe)
+{
+	MPLS_ENTER;
+	mpls_instrs_free (nhlfe->nhlfe_instr);
+	nhlfe->nhlfe_instr = NULL;
+	MPLS_EXIT;
+}
+
+int
+mpls_set_out_instrs (struct mpls_instr_elem *mie, int length,
+		struct mpls_nhlfe *nhlfe)
+{
+	struct mpls_instr *instr = NULL;
+	
+	/* Build temporary opcode set from mie */
+	if (!mpls_instrs_build(mie, &instr, length, MPLS_OUT, nhlfe))
+		return -1;
+
+	/* Commit the new ones */
+	if (nhlfe->nhlfe_instr)
+		mpls_instrs_free(nhlfe->nhlfe_instr);
+	nhlfe->nhlfe_instr = instr;
+	
+	return 0;
+}
+
+/**
+ *	mpls_set_out_label_instrs - program the opcodes for this NHLFE
+ *	@mir: request detailing the list of opcodes and data.
+ *
+ *	Update the NHLFE object (using the key in the request) with the passed
+ *	instrs/opcodes. Typically, once this function finishes for a PUSH/SET
+ *	Instruction Set, the refcount of a newly created NHLFE object is 2:
+ **/
+ 
+int 
+mpls_set_out_label_instrs (struct mpls_instr_req *mir)
+{
+	struct mpls_label *ml     = &mir->mir_label;
+	unsigned int key	  = mpls_label2key(0,ml);
+	struct mpls_nhlfe *nhlfe = mpls_get_nhlfe(key);
+	int ret;
+
+	if (unlikely(!nhlfe)) 
+		return -ESRCH;
+
+	ret = mpls_set_out_instrs (mir->mir_instr,mir->mir_instr_length, nhlfe);
+	mpls_nhlfe_release(nhlfe);
+	return ret;
+}
+
+/**
+ *	mpls_set_out_label_propagate_ttl - set the propagate_ttl status
+ *	@mol: request with the NHLFE key and desired propagate_ttl status
+ *
+ *	Update the NHLFE object (using the key in the request) with the
+ *	propagate_ttl from the request
+ **/
+ 
+int
+mpls_set_out_label_propagate_ttl(struct mpls_out_label_req *mol)
+{
+	unsigned int key	  = mpls_label2key(0,&mol->mol_label);
+	struct mpls_nhlfe *nhlfe = mpls_get_nhlfe(key);
+	if (!nhlfe)
+		return -ESRCH;
+
+	nhlfe->nhlfe_propagate_ttl = mol->mol_propagate_ttl;
+
+	mpls_nhlfe_release(nhlfe);
+	return 0;
+}
+
+/**
+ *	mpls_add_out_label - Add a new outgoing label to the database.
+ *	@out:request containing the label
+ *
+ *	Adds a new outgoing label to the outgoing tree. We first obtain
+ *	a unique unused key, check that the entry does not exist, 
+ *	allocate a new NHLFE object and reset it.
+ **/
+
+int 
+mpls_add_out_label (struct mpls_out_label_req *out, int seq, int pid) 
+{
+	struct mpls_nhlfe *nhlfe = NULL; 
+	unsigned int key	  = 0;
+	int retval		  = 0;
+
+	MPLS_ENTER;
+	BUG_ON(!out);
+
+	/* Create a new key */
+	key = mpls_get_out_key();
+
+	/* 
+	 * Check if the NHLFE is already in the tree. 
+	 * It should not exist. In fact, it is impossible :) 
+	 */
+	nhlfe = mpls_get_nhlfe (key);
+
+	if (unlikely(nhlfe)) {
+		MPLS_DEBUG("Node %u already exists in radix tree\n",key);
+
+		/* release the refcnt held by mpls_get_nhlfe */
+		mpls_nhlfe_release (nhlfe);
+		retval = -EEXIST;
+		goto error;
+	}
+
+	/* 
+	 * Allocate a new Output Information/Label,
+	 */
+	nhlfe = nhlfe_dst_alloc (key);
+	if (unlikely(!nhlfe)) {
+		retval = -ENOMEM;
+		goto error;
+	}
+
+	/* Insert into NHLFE tree */
+	spin_lock_bh (&mpls_nhlfe_lock);
+	if (unlikely(mpls_insert_nhlfe (key,nhlfe))) {
+		spin_unlock_bh (&mpls_nhlfe_lock);
+		nhlfe->u.dst.obsolete = 1;
+		dst_free (&nhlfe->u.dst);
+		goto error;
+	}
+
+	/* make sure that the dst system doesn't delete this until we're
+	 * done with it
+	 */
+	dst_hold(&nhlfe->u.dst);
+
+	mpls_nhlfe_hold(nhlfe);
+	spin_unlock_bh (&mpls_nhlfe_lock);
+
+	/* we need to hold a ref to the nhlfe while calling
+	 * mpls_nhlfe_event so it can't disappear
+	 */
+	mpls_nhlfe_event(MPLS_CMD_NEWNHLFE, nhlfe, seq, pid);
+	mpls_nhlfe_release(nhlfe);
+
+	out->mol_label.ml_type  = MPLS_LABEL_KEY;
+	out->mol_label.u.ml_key = key;
+
+error:
+	MPLS_EXIT;
+
+	return retval; 
+}
+
+/** 
+ *	mpls_del_out_label - Remove a NHLFE from the tree
+ *	@out: request.
+ **/
+
+int 
+mpls_del_out_label(struct mpls_out_label_req *out) 
+{
+	struct mpls_nhlfe *nhlfe = NULL;
+	unsigned int key;
+
+	MPLS_ENTER;
+
+	key = mpls_label2key(0,&out->mol_label);
+
+        nhlfe = mpls_get_nhlfe(key);
+	if (unlikely(!nhlfe)) {
+		MPLS_DEBUG("Node %u was not in tree\n",key);
+		MPLS_EXIT;
+		return  -ESRCH;
+	}
+
+	spin_lock_bh (&mpls_nhlfe_lock);
+
+	/* at this point a NHLFE that can be deleted will have a refcnt
+	 * of 2, one from mpls_get_nhlfe() we just executed and the
+	 * other that from when it was added to the tree
+	 */
+	if (atomic_read(&nhlfe->__refcnt) > 2) {
+		/* someone else is hold a refcnt, we can't delete */
+
+		/* release the refcnt we aquired in mpls_get_nhlfe() */
+		mpls_nhlfe_release (nhlfe);
+		spin_unlock_bh (&mpls_nhlfe_lock);
+
+		MPLS_DEBUG("Node %u is being used\n",key);
+		MPLS_EXIT;
+		return -EBUSY;
+	}
+
+	/*
+	 *	This code starts the process of removing a NHLFE from the
+	 *	system.  The first thing we we do it remove it from the tree
+	 *	so no one else can get a reference to it.  Then we notify the
+	 *	higher layer protocols that they should give up thier references
+	 *	soon (does not need to happen immediatly, the dst system allows
+	 *	for this.  Finally we schedule the RCU system to call
+	 *	dst_rcu_free() which waits until all CPUs have finished
+	 *	thier current work and then calls dst_rcu_free() which
+	 *	kicks the dst system into action once the dst system knows
+	 *	everyone is done using this "dst" it calls mpls_dst_destroy().
+	 */
+
+	/* remove the NHLFE from the tree (which decs the refcnt we held when
+	 * it was added to the tree)
+	 */
+	mpls_remove_nhlfe(nhlfe->nhlfe_key);
+	spin_unlock_bh (&mpls_nhlfe_lock);
+
+	mpls_nhlfe_event(MPLS_CMD_DELNHLFE, nhlfe, 0, 0);
+
+	/* destrory the instructions on this nhlfe, so as to no longer
+	 * hold refs to interfaces and other NHLFEs.
+	 *
+	 * Remember NHLFEs may stick around in the dst system even
+	 * after we've removed it from the tree.  So this will result
+	 * in traffic using the NHLFE to be dropped
+	 */
+	mpls_destroy_out_instrs (nhlfe);
+
+	/* let the dst system know we're done with this NHLFE and
+	 * schedule all higher layer protocol to give up their references */
+	dst_release(&nhlfe->u.dst);
+	nhlfe->u.dst.obsolete = 1;
+	mpls_proto_cache_flush_all(&init_net);
+
+	/* since high layer protocols may still be using us in there caches
+	 * we need to use call_rcu() and dst_rcu_free() to take care
+	 * of actually cleaning up NHLFE
+	 */
+	call_rcu(&nhlfe->u.dst.rcu_head, dst_rcu_free);
+
+	/* release the refcnt we aquired in mpls_get_nhlfe() */
+	mpls_nhlfe_release (nhlfe);
+
+	MPLS_EXIT;
+	return 0;
+}
+
+/**
+ * mpls_set_out_label_mtu - change the MTU for this NHLFE.
+ * @out: Request containing the new MTU.
+ *
+ * Update the NHLFE object (using the key in the request) with the passed
+ * MTU.
+ **/
+
+int mpls_set_out_label_mtu(struct mpls_out_label_req *out)
+{
+	struct mpls_nhlfe *nhlfe = NULL;
+	int retval = 0;
+	unsigned int key;
+
+	BUG_ON(!out);
+	MPLS_ENTER;
+
+	key = out->mol_label.u.ml_key;
+
+	nhlfe = mpls_get_nhlfe(key);
+
+	if (unlikely(!nhlfe)) {
+		MPLS_DEBUG("Node %u does not exists in radix tree\n", key);
+		MPLS_EXIT;
+		return -ESRCH;
+	}
+
+	/* Update the MTU if possible */
+	if (nhlfe->nhlfe_mtu_limit >= out->mol_mtu) {
+		nhlfe->nhlfe_mtu = out->mol_mtu;
+	} else {
+		MPLS_DEBUG("MTU is larger than lower layer (%d > %d)\n",
+			out->mol_mtu, nhlfe->nhlfe_mtu_limit);
+
+		/* release the refcnt held by mpls_get_nhlfe */
+		mpls_nhlfe_release(nhlfe);
+		return -EINVAL;
+	}
+
+	/* release the refcnt held by mpls_get_nhlfe */
+	mpls_nhlfe_release(nhlfe);
+
+	/* force the layer 3 protocols to re-find and dsts (NHLFEs),
+	 * thus picking up the new MTU
+	 */
+	mpls_proto_cache_flush_all(&init_net);
+
+	MPLS_EXIT;
+	return retval;
+}
+
+int __init mpls_nhlfe_init(void)
+{
+	nhlfe_dst_ops.kmem_cachep = kmem_cache_create("nhlfe_dst_cache",
+		sizeof(struct mpls_nhlfe), 0, SLAB_HWCACHE_ALIGN, NULL);
+
+	if (!nhlfe_dst_ops.kmem_cachep) {
+		printk(MPLS_ERR "MPLS: failed to alloc nhlfe_dst_cache\n");
+		return -ENOMEM;
+	}
+
+	return 0;
+}
+
+void __exit mpls_nhlfe_exit(void)
+{
+	if (nhlfe_dst_ops.kmem_cachep)
+		kmem_cache_destroy(nhlfe_dst_ops.kmem_cachep);
+	return;
+}
+
+EXPORT_SYMBOL(mpls_get_nhlfe);
