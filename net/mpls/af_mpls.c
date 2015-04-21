--- mpls-linux-2.6.35.y/net/mpls/af_mpls.c	1970-01-01 08:00:00.000000000 +0800
+++ linux-2.6.35-vpls/net/mpls/af_mpls.c	2015-04-20 20:24:43.759583630 +0800
@@ -0,0 +1,134 @@
+/*****************************************************************************
+ * MPLS
+ *      An implementation of the MPLS (MultiProtocol Label
+ *      Switching) Architecture for Linux.
+ *
+ * af_mpls.c
+ *	 * PF_MPLS 
+ *
+ * $Id$
+ *
+ * Authors:
+ *	  James Leu	<jleu@mindspring.com>
+ *
+ *   (c) 2003	James Leu	<jleu@mindspring.com>
+ *
+ *      This program is free software; you can redistribute it and/or
+ *      modify it under the terms of the GNU General Public License
+ *      as published by the Free Software Foundation; either version
+ *      2 of the License, or (at your option) any later version.
+ *
+ * $ChangeLog$
+ *****************************************************************************
+ */
+
+#include <generated/autoconf.h>
+#include <linux/module.h>
+#include <linux/init.h>
+#include <linux/slab.h>
+#include <net/sock.h>
+#include <net/net_namespace.h>
+#include <linux/net.h>
+#include <linux/errno.h>
+#include <linux/types.h>
+#include <linux/socket.h>
+
+static int mpls_release(struct socket *sock) {
+	return 0;
+}
+
+static struct proto mpls_proto = {
+	.name =		"MPLS",
+	.owner =	 THIS_MODULE,
+	.obj_size =	 sizeof(struct sock),
+};
+
+struct proto_ops mpls_sk_ops = {
+	.family =	PF_MPLS,
+	.owner =	THIS_MODULE,
+	.release =	mpls_release,
+	.bind =		sock_no_bind,
+	.connect =	sock_no_connect,
+	.socketpair =	sock_no_socketpair,
+	.accept =	sock_no_accept,
+	.getname =	sock_no_getname,
+	.poll =		sock_no_poll,
+	.ioctl =	sock_no_ioctl,
+	.listen =       sock_no_listen,
+	.shutdown =	sock_no_shutdown,
+	.setsockopt =	sock_no_setsockopt,
+	.getsockopt =	sock_no_getsockopt,
+	.sendmsg =	sock_no_sendmsg,
+	.recvmsg =	sock_no_recvmsg,
+	.mmap =		sock_no_mmap,
+	.sendpage =	sock_no_sendpage,
+};
+
+/* destruction routine */
+                                                                                
+static void mpls_sock_destruct(struct sock *sk)
+{
+        __skb_queue_purge(&sk->sk_receive_queue);
+        __skb_queue_purge(&sk->sk_error_queue);
+
+        WARN_ON(atomic_read(&sk->sk_rmem_alloc));
+        WARN_ON(atomic_read(&sk->sk_wmem_alloc));
+        WARN_ON(sk->sk_wmem_queued);
+        WARN_ON(sk->sk_forward_alloc);
+
+        dst_release(sk->sk_dst_cache);
+}
+
+/*
+ *      Create an mpls socket.
+ */
+                                                                                
+static int mpls_create(struct net *net, struct socket *sock, int protocol,
+                       int kern)
+{
+	struct sock *sk;
+
+        if (net != &init_net)
+		return -EAFNOSUPPORT;
+
+	sock->state = SS_UNCONNECTED;
+	sock->ops = &mpls_sk_ops;
+
+	sk = sk_alloc(net, PF_INET, GFP_KERNEL, &mpls_proto);
+        if (!sk)
+                return -1;
+
+	sock_init_data(sock, sk);
+
+	sk->sk_destruct    = mpls_sock_destruct;
+	sk->sk_family      = PF_MPLS;
+	sk->sk_protocol    = 0;
+	sk->sk_backlog_rcv = sk->sk_prot->backlog_rcv;
+
+	sock_reset_flag(sk, SOCK_ZAPPED);
+
+	return 0;
+}
+
+struct net_proto_family mpls_family_ops = {
+	.family = PF_MPLS,
+	.create = mpls_create,
+	.owner  = THIS_MODULE,
+};
+
+int __init mpls_sock_init(void)
+{
+	int rc;
+	if ((rc = proto_register(&mpls_proto, 0)))
+		return rc;
+
+        sock_register(&mpls_family_ops);
+
+	return 0;
+}
+
+void __exit mpls_sock_exit(void)
+{
+	sock_unregister(AF_MPLS);
+	proto_unregister(&mpls_proto);
+}
