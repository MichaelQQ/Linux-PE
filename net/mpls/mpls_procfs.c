--- mpls-linux-2.6.35.y/net/mpls/mpls_procfs.c	1970-01-01 08:00:00.000000000 +0800
+++ linux-2.6.35-vpls/net/mpls/mpls_procfs.c	2015-04-20 20:24:43.759583630 +0800
@@ -0,0 +1,139 @@
+/*
+ *      Network mpls interface for protocols that live below L3 and above L2
+ *
+ *		This program is free software; you can redistribute it and/or
+ *		modify it under the terms of the GNU General Public License
+ *		as published by the Free Software Foundation; either version
+ *		2 of the License, or (at your option) any later version.
+ *
+ *	Heavily borrowed from dev_remove_pack/dev_add_pack
+ *
+ *	Authors:	James R. Leu <jleu@mindspring.com>
+ */
+
+#include <generated/autoconf.h>
+#include <linux/init.h>
+#include <linux/kernel.h>
+#include <linux/spinlock.h>
+#include <asm/byteorder.h>
+#include <linux/list.h>
+#include <net/mpls.h>
+#include <linux/proc_fs.h>
+#include <linux/seq_file.h>
+#include <net/net_namespace.h>
+
+extern spinlock_t mpls_proto_lock;
+extern struct list_head mpls_proto_list;
+
+/*
+ * MODULE Information and attributes
+ */
+
+MODULE_AUTHOR("James R. Leu <jleu@mindspring.com>");
+MODULE_DESCRIPTION("net-mpls procfs module");
+MODULE_LICENSE("GPL");
+
+/*
+ * The following few functions build the content of /proc/net/mpls
+ */
+
+/* starting at mpls, find the next registered protocol */
+static struct mpls_prot_driver *mpls_skip(struct mpls_prot_driver *mpls)
+{
+	struct mpls_prot_driver *mpls1;
+	int next = 0;
+
+	if (!mpls)
+		next = 1;
+		
+	list_for_each_entry(mpls1, &mpls_proto_list, list) {
+		if (next)
+			return mpls1;
+
+		if (mpls1 == mpls)
+			next = 1;
+	}
+
+	return NULL;
+}
+
+										
+/* start read of /proc/net/mpls */
+static void *mpls_seq_start(struct seq_file *seq, loff_t *pos)
+{
+	struct mpls_prot_driver *mpls;
+	loff_t i = 1;
+
+	spin_lock_bh(&mpls_proto_lock);
+
+	if (*pos == 0)
+		return SEQ_START_TOKEN;
+
+	for (mpls = mpls_skip(NULL); mpls && i < *pos;
+		mpls = mpls_skip(mpls), ++i);
+										
+	return (i == *pos) ? mpls : NULL;
+}
+
+static void *mpls_seq_next(struct seq_file *seq, void *v, loff_t *pos)
+{
+	++*pos;
+										
+	return mpls_skip((v == SEQ_START_TOKEN)
+			    ? NULL
+			    : (struct mpls_prot_driver *)v);
+}
+										
+static void mpls_seq_stop(struct seq_file *seq, void *v)
+{
+	spin_unlock_bh(&mpls_proto_lock);
+}
+
+static int mpls_seq_show(struct seq_file *seq, void *v)
+{
+	struct mpls_prot_driver* mpls = (struct mpls_prot_driver*)v;
+	if (v != SEQ_START_TOKEN)
+		seq_printf(seq, "%s\t%d\n",
+		    mpls->name ? mpls->name : "(none)",
+		    atomic_read(&mpls->__refcnt));
+	return 0;
+}
+
+/*
+ *      Generic /proc/net/mpls file and inode operations
+ */
+										
+static struct seq_operations mpls_seq_ops = {
+	.start = mpls_seq_start,
+	.next = mpls_seq_next,
+	.stop = mpls_seq_stop,
+	.show = mpls_seq_show,
+};
+										
+static int mpls_seq_open(struct inode *inode, struct file *file)
+{
+	return seq_open(file, &mpls_seq_ops);
+}
+										
+static struct file_operations mpls_seq_fops = {
+	.owner   = THIS_MODULE,
+	.open    = mpls_seq_open,
+	.read    = seq_read,
+	.llseek  = seq_lseek,
+	.release = seq_release,
+};
+
+int __init mpls_procfs_init(void)
+{
+	if (!proc_net_fops_create(&init_net, "mpls",  S_IRUGO,
+				  &mpls_seq_fops)) {
+		printk(MPLS_ERR "MPLS: failed to register with procfs\n");
+		return -ENOMEM;
+	}
+	return 0;
+}
+
+void __exit mpls_procfs_exit(void)
+{
+	proc_net_remove(&init_net, "mpls");
+}
