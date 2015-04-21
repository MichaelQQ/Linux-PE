--- mpls-linux-2.6.35.y/net/mpls/mpls_if.c	1970-01-01 08:00:00.000000000 +0800
+++ linux-2.6.35-vpls/net/mpls/mpls_if.c	2015-04-20 20:24:43.759583630 +0800
@@ -0,0 +1,282 @@
+/*****************************************************************************
+ * MPLS
+ *      An implementation of the MPLS (MultiProtocol Label
+ *      Switching) Architecture for Linux.
+ *
+ * mpls_if.c
+ *         * Allocation/Deallocation of per netdevice MPLS data (labelspace)
+ *         * Query/Update MPLS labelspace functions.
+ *
+ * Authors:
+ *          James Leu        <jleu@mindspring.com>
+ *          Ramon Casellas   <casellas@infres.enst.fr>
+ *
+ *   (c) 1999-2010   James Leu        <jleu@mindspring.com>
+ *   (c) 2003-2004   Ramon Casellas   <casellas@infres.enst.fr>
+ *
+ *      This program is free software; you can redistribute it and/or
+ *      modify it under the terms of the GNU General Public License
+ *      as published by the Free Software Foundation; either version
+ *      2 of the License, or (at your option) any later version.
+ *
+ *****************************************************************************
+ */
+
+#include <generated/autoconf.h>
+#include <asm/uaccess.h>
+#include <linux/init.h>
+#include <linux/netdevice.h>
+#include <linux/in.h>           /* must be before route.h */
+#include <linux/ip.h>           /* must be before route.h */
+#include <linux/inetdevice.h>   /* must be before route.h */
+#include <net/route.h>
+#include <net/mpls.h>
+#include <linux/genetlink.h>
+#include <net/net_namespace.h>
+
+/*
+ * MPLS info radix tree and corresponding lock
+ */
+RADIX_TREE(mpls_if_tree, GFP_ATOMIC);
+
+DEFINE_SPINLOCK(mpls_if_lock);
+
+
+/**
+ *	mpls_create_if_info - allocate memory for the MPLS net_device extension
+ *
+ *	Returns a pointer to the allocated struct.
+ *	RCAS: From process context only. May sleep.
+ **/
+
+struct mpls_interface *
+mpls_create_if_info (void)
+{
+	struct mpls_interface *mif =
+	    kmalloc(sizeof(struct mpls_interface), GFP_KERNEL);
+	if (unlikely(!mif)) 
+		return NULL;
+
+	memset(mif, 0, sizeof(struct mpls_interface));
+	mif->labelspace = -1;
+	INIT_LIST_HEAD(&mif->list_out);
+	INIT_LIST_HEAD(&mif->list_in);
+	return mif;
+}
+
+
+/**
+ *	mpls_delete_if_info - free memory stored for per netdevice MPLS data
+ *	@dev: netdevice
+ *	
+ *	Deallocation of MPLS netdevice data
+ **/
+
+inline void 
+mpls_delete_if_info (struct net_device *dev)
+{
+	struct mpls_interface *mif;
+	spin_lock_bh (&mpls_if_lock);
+	mif = radix_tree_delete (&mpls_if_tree, dev->ifindex);
+	spin_unlock_bh (&mpls_if_lock);
+
+	if (mif)
+		kfree (mif);
+}
+
+struct mpls_interface *
+mpls_get_if_info (unsigned int key)
+{
+	struct mpls_interface *mif;
+	spin_lock_bh (&mpls_if_lock);
+	mif = radix_tree_lookup (&mpls_if_tree,key);
+	spin_unlock_bh (&mpls_if_lock);
+	return mif;
+}
+
+/**
+ *	__mpls_get_labelspace - Get the interface  label space
+ *	@dev: device 
+ *
+ *	See mpls_get_labelspace for comments.
+ *	Returns the labelspace
+ **/
+
+static inline int 
+__mpls_get_labelspace (struct net_device *dev)
+{
+	struct mpls_interface *mif = mpls_get_if_info(dev->ifindex);
+	return (mif) ? mif->labelspace : -1;
+}
+
+
+/**
+ *	mpls_get_labelspace_by_name - Get the interface  label space
+ *	@name: name of the interface
+ *
+ *	See mpls_get_labelspace for comments.
+ *	Returns the labelspace
+ **/
+
+int 
+mpls_get_labelspace_by_name (const char* name)
+{
+	int result = -1;
+	struct net_device *dev = dev_get_by_name (&init_net, name);
+	if (dev) {
+		result = __mpls_get_labelspace (dev);
+		dev_put (dev);
+	}
+	return result;
+}
+
+/**
+ *	mpls_set_labelspace_by_index - Get the interface  label space
+ *	@ifindex:  interface index 
+ *
+ *	See mpls_get_labelspace for comments.
+ *	Returns the labelspace
+ **/
+
+int 
+mpls_get_labelspace_by_index (int ifindex)
+{
+	struct mpls_interface *mif = mpls_get_if_info(ifindex);
+	return (mif) ? mif->labelspace : -1;
+}
+
+/**
+ *	mpls_get_labelspace - Get the label space for the interface
+ *	@req: mpls_labelspace_req struct with the query data. In particular,
+ *	     contains the interface index in req->mls_ifindex.
+ *
+ *	Returns 0 on sucess and sets the label space for the netdevice in
+ *	req->mls_ifindex. The labelspace in req->mls_ifindex may be -1 if MPLS
+ *	was not active on the interface.
+ **/
+
+inline int 
+mpls_get_labelspace(struct mpls_labelspace_req *req)
+{
+	return mpls_get_labelspace_by_index (req->mls_ifindex);
+}
+
+/**
+ *	__mpls_set_labelspace - Set a label space for the interface.
+ *	@dev: device 
+ *	@labelspace: new labelspace
+ *
+ *	See mpls_set_labelspace for comments.
+ *	Returns 0 on success.
+ **/
+
+static int 
+__mpls_set_labelspace (struct net_device *dev, int labelspace)
+{
+	struct mpls_interface *mif = mpls_get_if_info(dev->ifindex);
+	int err;
+
+	MPLS_ENTER;
+	if (!mif && labelspace != -1) {
+		mif = mpls_create_if_info ();
+		if (unlikely(!mif)) {
+			MPLS_DEBUG("Err: Set labelspace for %s to %d\n",
+				dev->name, labelspace);
+			MPLS_EXIT;
+			return -ENOMEM;
+		}
+		/* Actual assignment happens here */
+		mif->labelspace = labelspace;
+
+		spin_lock_bh (&mpls_if_lock);
+		err = radix_tree_insert(&mpls_if_tree, dev->ifindex, mif);
+		spin_unlock_bh (&mpls_if_lock);
+		if (unlikely(err)) {
+			MPLS_DEBUG("Error adding if index %u to radix tree\n",dev->ifindex);
+			MPLS_EXIT;
+			return -ENOMEM;
+		} else {
+			MPLS_DEBUG("Set labelspace for %s to %d\n",
+				dev->name, labelspace);
+		}
+	} else {
+		if (labelspace == -1) {
+			MPLS_DEBUG("Resetting labelspace for %s to %d\n",
+				dev->name,-1);
+			mpls_delete_if_info (dev);
+		} else {
+			mif->labelspace = labelspace;
+		}
+			
+	}
+	mpls_labelspace_event(MPLS_CMD_SETLABELSPACE, dev);
+	MPLS_EXIT;
+	return 0;
+}
+
+/**
+ *	mpls_set_labelspace_by_name - Set a label space for the interface.
+ *	@name: name of the interface
+ *	@labelspace: new labelspace
+ *
+ *	See mpls_set_labelspace for comments.
+ *	Returns 0 on success.
+ **/
+
+int 
+mpls_set_labelspace_by_name (const char* name, int labelspace)
+{
+	int result = -1;
+	struct net_device *dev = dev_get_by_name (&init_net, name);
+	if (dev) {
+		result = __mpls_set_labelspace (dev, labelspace);
+		dev_put (dev);
+	}
+	return result;
+}
+
+/**
+ *	mpls_set_labelspace_by_index - Set a label space for the interface.
+ *	@ifindex:  interface index 
+ *	@labelspace: new labelspace
+ *
+ *	See mpls_set_labelspace for comments.
+ *	Returns 0 on success.
+ **/
+
+int 
+mpls_set_labelspace_by_index (int ifindex, int labelspace)
+{
+	int result = -1;
+	struct net_device *dev = dev_get_by_index (&init_net, ifindex);
+	if (dev) {
+		result = __mpls_set_labelspace (dev, labelspace);
+		dev_put (dev);
+	}
+	return result;
+}
+
+/**
+ *	mpls_set_labelspace - Set a label space for the interface.
+ *	@req: mpls_labelspace_req struct with the update data. In particular,
+ *	     contains the interface index in req->mls_ifindex, and the new
+ *	     labelspace in req->mls_labelspace.
+ *
+ *	This function assigns a label space to a particular net device. In
+ *	the current implementation, the mif is store in a radix trie by the
+ *	netdevice ifindex.  The mif is dynamically allocated here,
+ *	using mpls_create_if_info().
+ *	Returns 0 on success.
+ **/
+
+int 
+mpls_set_labelspace (struct mpls_labelspace_req *req)
+{
+	int result = -1; 
+	struct net_device *dev = dev_get_by_index (&init_net, req->mls_ifindex);
+	if (dev) {
+		result = __mpls_set_labelspace (dev, req->mls_labelspace);
+		dev_put (dev);
+	}
+	return result;
+}
