--- mpls-linux-2.6.35.y/net/mpls/mpls_proto.c	1970-01-01 08:00:00.000000000 +0800
+++ linux-2.6.35-vpls/net/mpls/mpls_proto.c	2015-04-20 20:24:43.759583630 +0800
@@ -0,0 +1,154 @@
+/*****************************************************************************
+ * MPLS
+ *      An implementation of the MPLS (MultiProtocol Label
+ *      Switching) Architecture for Linux.
+ *
+ * mpls_proto.c: MPLS Proto management
+ *
+ * Copyright (C) David S. Miller (davem@redhat.com),
+ *		 James R. Leu (jleu@mindspring.com)
+ *
+ *      This program is free software; you can redistribute it and/or
+ *      modify it under the terms of the GNU General Public License
+ *      as published by the Free Software Foundation; either version
+ *      2 of the License, or (at your option) any later version.
+ *
+ * Changes:
+ *	RCAS: minor changes (formatting) and added addr
+ *	JLEU: added mpls_prot_cache_flush_all()
+ *	JLEU: rewrote most of the functions to allow for more
+ *	       families then just IPv4 and IPv6
+ *****************************************************************************/
+
+#include <generated/autoconf.h>
+#include <linux/types.h>
+#include <linux/kernel.h>
+#include <linux/sched.h>
+#include <linux/string.h>
+#include <linux/mm.h>
+#include <linux/errno.h>
+#include <linux/interrupt.h>
+#include <linux/skbuff.h>
+#include <linux/rculist.h>
+#include <net/mpls.h>
+
+DEFINE_SPINLOCK(mpls_proto_lock);
+LIST_HEAD(mpls_proto_list);
+
+int mpls_proto_add(struct mpls_prot_driver *proto)
+{
+        spin_lock_bh(&mpls_proto_lock);
+
+        atomic_set(&proto->__refcnt, 1);
+        list_add_rcu(&proto->list, &mpls_proto_list);
+
+        spin_unlock_bh(&mpls_proto_lock);
+	return 0;
+}
+
+int mpls_proto_remove(struct mpls_prot_driver *proto)
+{
+        struct mpls_prot_driver *proto1;
+        int retval = -EPROTONOSUPPORT;
+
+        spin_lock_bh(&mpls_proto_lock);
+
+        list_for_each_entry(proto1, &mpls_proto_list, list) {
+                if (proto == proto1) {
+                        if (atomic_read(&proto->__refcnt) != 1) {
+                                retval = -EADDRINUSE;
+                        } else {
+                                list_del_rcu(&proto->list);
+                                retval = 0;
+                        }
+                        break;
+                }
+        }
+        spin_unlock_bh(&mpls_proto_lock);
+
+        synchronize_net();
+        return retval;
+}
+
+struct mpls_prot_driver *mpls_proto_find_by_family(unsigned short fam)
+{
+        struct mpls_prot_driver *proto;
+
+	rcu_read_lock();
+        list_for_each_entry_rcu(proto, &mpls_proto_list, list) {
+                if (fam == proto->family) {
+                        mpls_proto_hold(proto);
+                        goto out;
+                }
+        }
+        proto = NULL;
+out:
+	rcu_read_unlock();
+
+        return proto;
+}
+
+struct mpls_prot_driver *mpls_proto_find_by_ethertype(unsigned short type)
+{
+        struct mpls_prot_driver *proto;
+
+	rcu_read_lock();
+        list_for_each_entry_rcu(proto, &mpls_proto_list, list) {
+                if (type == proto->ethertype) {
+                        mpls_proto_hold(proto);
+                        goto out;
+                }
+        }
+        proto = NULL;
+out:
+	rcu_read_unlock();
+
+        return proto;
+}
+
+struct mpls_prot_driver *mpls_proto_find_by_name(char *name)
+{
+        struct mpls_prot_driver *proto;
+
+	rcu_read_lock();
+        list_for_each_entry_rcu(proto, &mpls_proto_list, list) {
+                if (!strncmp(name, proto->name, MPLSPROTONAMSIZ)) {
+                        mpls_proto_hold(proto);
+                        goto out;
+                }
+        }
+        proto = NULL;
+out:
+	rcu_read_unlock();
+
+        return proto;
+}
+
+void mpls_proto_cache_flush_all(struct net *net)
+{
+        struct mpls_prot_driver *proto;
+
+	rcu_read_lock();
+        list_for_each_entry_rcu(proto, &mpls_proto_list, list) {
+		proto->cache_flush(net);
+        }
+	rcu_read_unlock();
+}
+
+void __init mpls_proto_init(void)
+{
+	printk("MPLS: protocol driver interface - <jleu@mindspring.com>\n");
+}
+
+void __exit mpls_proto_exit(void)
+{
+}
+
+EXPORT_SYMBOL(mpls_proto_add);
+EXPORT_SYMBOL(mpls_proto_remove);
+EXPORT_SYMBOL(mpls_proto_find_by_family);
+EXPORT_SYMBOL(mpls_proto_find_by_ethertype);
+EXPORT_SYMBOL(mpls_proto_find_by_name);
+EXPORT_SYMBOL(mpls_proto_cache_flush_all);
+EXPORT_SYMBOL(mpls_proto_lock);
+EXPORT_SYMBOL(mpls_proto_list);
