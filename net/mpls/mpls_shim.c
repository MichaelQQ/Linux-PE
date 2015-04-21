--- mpls-linux-2.6.35.y/net/mpls/mpls_shim.c	1970-01-01 08:00:00.000000000 +0800
+++ linux-2.6.35-vpls/net/mpls/mpls_shim.c	2015-04-20 20:24:43.759583630 +0800
@@ -0,0 +1,105 @@
+/*****************************************************************************
+ * MPLS
+ *      An implementation of the MPLS (MultiProtocol Label
+ *      Switching Architecture) for Linux.
+ *
+ * Authors:
+ *          James Leu        <jleu@mindspring.com>
+ *
+ *   (c) 1999-2005   James Leu        <jleu@mindspring.com>
+ *
+ *      This program is free software; you can redistribute it and/or
+ *      modify it under the terms of the GNU General Public License
+ *      as published by the Free Software Foundation; either version
+ *      2 of the License, or (at your option) any later version.
+ *
+ * Changes:
+ * 20051122 JLEU
+ *	- seperate shim code from init
+ ****************************************************************************/
+
+#include <generated/autoconf.h>
+#include <linux/kernel.h>
+#include <linux/module.h>
+#include <linux/init.h>
+#include <net/shim.h>
+#include <net/mpls.h>
+
+/**
+ *	mpls_set_nexthop2
+ *	@nhlfe: the nhlfe object to apply to the dst
+ *	@dst: dst_entry 
+ *
+ *	Called from outside the MPLS subsystem. 
+ **/
+
+int mpls_set_nexthop2(struct mpls_nhlfe *nhlfe, struct dst_entry *dst)
+{
+	MPLS_ENTER;
+
+	dst->metrics[RTAX_MTU-1] = nhlfe->nhlfe_mtu;
+	dst->child = dst_clone(&nhlfe->u.dst);
+	MPLS_DEBUG("nhlfe: %p mtu: %d dst: %p\n", nhlfe, nhlfe->nhlfe_mtu,
+		&nhlfe->u.dst);
+
+	MPLS_EXIT;
+	return 0;
+}
+
+/**
+ *	mpls_set_nexthop
+ *	@shim:holds the key to look up the NHLFE object to apply.
+ *	@dst: dst_entry 
+ *
+ *	Called from outside the MPLS subsystem. 
+ **/
+
+int mpls_set_nexthop (struct shim_blk *sblk, struct dst_entry *dst)
+{
+	struct mpls_nhlfe *nhlfe = NULL;
+	unsigned int key;
+	int ret;
+
+	MPLS_ENTER;
+
+	memcpy(&key, sblk->data, sizeof(key));
+	nhlfe = mpls_get_nhlfe(key);
+	if (unlikely(!nhlfe)) {
+		MPLS_EXIT;
+		return -ENXIO;
+	}
+
+	ret = mpls_set_nexthop2(nhlfe, dst);
+	mpls_nhlfe_release(nhlfe);
+	MPLS_EXIT;
+ 	return ret;
+}
+
+/**
+ *	mpls_uc_shim - "SPECIAL" next hop Management for MPLS UC traffic.
+ *	@name: name of the struct.
+ *	@build: Callback used to build
+ *
+ *	e.g. for a MPLS enabled iproute2:
+ *	ip route add a.b.c.d/n via x.y.z.w shim mpls 0x2
+ *	The key (0x2) is the "data" for NHLFE lookup.
+ **/
+ 
+static struct shim mpls_uc_shim = {
+	.name = "mpls",
+	.build = mpls_set_nexthop,
+};
+
+void __init mpls_shim_init (void) 
+{
+	shim_proto_add(&mpls_uc_shim);
+}
+
+void __exit mpls_shim_exit (void)
+{
+	shim_proto_remove (&mpls_uc_shim);
+	synchronize_net();
+}
+
+EXPORT_SYMBOL(mpls_set_nexthop2);
+EXPORT_SYMBOL(mpls_set_nexthop);
