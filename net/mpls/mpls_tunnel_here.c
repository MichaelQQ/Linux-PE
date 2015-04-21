--- mpls-linux-2.6.35.y/net/mpls/mpls_tunnel_here.c	1970-01-01 08:00:00.000000000 +0800
+++ linux-2.6.35-vpls/net/mpls/mpls_tunnel_here.c	2015-04-20 20:24:43.759583630 +0800
@@ -0,0 +1,881 @@
+/*****************************************************************************
+ * MPLS
+ *      An implementation of the MPLS (MultiProtocol Label
+ *      Switching) Architecture for Linux.
+ *
+ * mpls_tunnel.c
+ *         * Management of MPLS tunnels, virtual devices named by default
+ *           mpls%d and that can be managed using userspace tools like
+ *           ip route, ifconfig, etc. As per RFC, LSPs are unidirectional.
+ *  Usage:
+ *         Creation    : mpls_tunnel_create
+ *         Destruction : mpls_tunnel_destroy
+ *         EXPORT_SYMBOL(mpls_tunnel_create);
+ *         EXPORT_SYMBOL(mpls_tunnel_destroy);
+ *
+ * Authors:
+ *   (c) 1999-2005   James Leu        <jleu@mindspring.com>
+ *   (c) 2003-2004   Ramon Casellas   <casellas@infres.enst.fr>
+ *
+ *      This program is free software; you can redistribute it and/or
+ *      modify it under the terms of the GNU General Public License
+ *      as published by the Free Software Foundation; either version
+ *      2 of the License, or (at your option) any later version.
+ *
+ * ChangeLog
+ *	v-0.97 20040207 RCAS 
+ *		o set up netlink links. 
+ *	v-0.98 20040208 RCAS 
+ *		o remove private list. 
+ *		o fixed some MTU issues. Use dev_set_mtu
+ *	20050105 JLEU
+ *		o implement netlink interface
+ *	20050827 JLEU
+ *		o remove netlink code
+ *		o module loading creates one interface, unload deletes it
+ *		o implemented device IOCTL for setting NHLFE
+ *****************************************************************************/
+
+//#include <linux/config.h>
+#include <linux/in.h>
+#include <linux/init.h>
+#include <linux/kernel.h>
+#include <linux/skbuff.h>
+#include <linux/if_arp.h>
+#include <linux/netdevice.h>
+#include <linux/rtnetlink.h>
+#include <net/mpls.h>
+#include <linux/genetlink.h>
+
+
+
+#include <linux/module.h>
+
+#include <linux/moduleparam.h>
+
+#include <linux/sched.h>
+#include <linux/kernel.h> /* printk() */
+#include <linux/slab.h> /* kmalloc() */
+#include <linux/errno.h>  /* error codes */
+#include <linux/types.h>  /* size_t */
+#include <linux/interrupt.h> /* mark_bh */
+
+#include <linux/in.h>
+#include <linux/netdevice.h>   /* struct device, and other headers */
+#include <linux/etherdevice.h> /* eth_type_trans */
+#include <linux/ip.h>          /* struct iphdr */
+#include <linux/tcp.h>         /* struct tcphdr */
+#include <linux/skbuff.h>
+
+#include <linux/in6.h>
+#include <asm/checksum.h>
+
+
+/* Obtain mentor netdevice for a given (private) tunnel */
+#define mpls_mtp2dev(MPLSMTP) \
+	((struct net_device *)((MPLSMTP)->mtp_dev))
+
+/* These are the flags in the statusword */
+#define MPLS_RX_INTR 0x0001  //add by here
+#define MPLS_TX_INTR 0x0002  //add by here
+
+int pool_size = 8; //add by here
+module_param(pool_size, int, 0); //add by here
+/*
+ * Transmitter lockup simulation, normally disabled.
+ */
+static int lockup = 0;
+module_param(lockup, int, 0);
+
+static void mpls_tx_timeout(struct net_device *dev); //add by here
+void (*mpls_interrupt)(int, void *, struct pt_regs *); //add by here
+/*
+ * Do we run in NAPI mode?
+ */
+
+
+//Under those code to receive packet 
+
+/*
+ * Set up a device's packet pool.
+ */
+void mpls_tunnel_setup_pool(struct net_device *dev)
+{
+	struct mpls_tunnel_private *priv = netdev_priv(dev);
+	int i;
+	struct mpls_packet *pkt;
+
+	priv->ppool = NULL;
+	for (i = 0; i < pool_size; i++) {
+		pkt = kmalloc (sizeof (struct mpls_packet), GFP_KERNEL);
+		if (pkt == NULL) {
+			printk (KERN_NOTICE "Ran out of memory allocating packet pool\n");
+			return;
+		}
+		pkt->dev = dev;
+		pkt->next = priv->ppool;
+		priv->ppool = pkt;
+	}
+}
+
+void mpls_teardown_pool(struct net_device *dev)
+{
+	struct mpls_tunnel_private *priv = netdev_priv(dev);
+	struct mpls_packet *pkt;
+    
+	while ((pkt = priv->ppool)) {
+		priv->ppool = pkt->next;
+		kfree (pkt);
+		/* FIXME - in-flight packets ? */
+	}
+}  
+/*
+ * Buffer/pool management.
+ */
+struct mpls_packet *mpls_get_tx_buffer(struct net_device *dev)
+{
+	struct mpls_tunnel_private *priv = netdev_priv(dev);
+	unsigned long flags;
+	struct mpls_packet *pkt;
+    
+	spin_lock_irqsave(&priv->lock, flags);
+	pkt = priv->ppool;
+	priv->ppool = pkt->next;
+	if (priv->ppool == NULL) {
+		printk (KERN_INFO "Pool empty\n");
+		netif_stop_queue(dev);
+	}
+	spin_unlock_irqrestore(&priv->lock, flags);
+	return pkt;
+}
+
+void mpls_release_buffer(struct mpls_packet *pkt)
+{
+	unsigned long flags;
+	struct mpls_tunnel_private *priv = netdev_priv(pkt->dev);
+	spin_lock_irqsave(&priv->lock, flags);
+	pkt->next = priv->ppool;
+	priv->ppool = pkt;
+	spin_unlock_irqrestore(&priv->lock, flags);
+	if (netif_queue_stopped(pkt->dev) && pkt->next == NULL)
+		netif_wake_queue(pkt->dev);
+}
+
+void mpls_enqueue_buf(struct net_device *dev, struct mpls_packet *pkt)
+{
+	unsigned long flags;
+	struct mpls_tunnel_private *priv = netdev_priv(dev);
+
+	spin_lock_irqsave(&priv->lock, flags);
+	pkt->next = priv->rx_queue;  /* FIXME - misorders packets */
+	priv->rx_queue = pkt;
+	spin_unlock_irqrestore(&priv->lock, flags);
+}
+
+struct mpls_packet *mpls_dequeue_buf(struct net_device *dev)
+{
+	struct mpls_tunnel_private *priv = netdev_priv(dev);
+	struct mpls_packet *pkt;
+	unsigned long flags;
+
+	spin_lock_irqsave(&priv->lock, flags);
+	pkt = priv->rx_queue;
+	if (pkt != NULL)
+		priv->rx_queue= pkt->next;
+	spin_unlock_irqrestore(&priv->lock, flags);
+	return pkt;
+}
+
+/*
+ * Enable and disable receive interrupts.
+ */
+static void mpls_rx_ints(struct net_device *dev, int enable)
+{
+	struct mpls_tunnel_private *priv = netdev_priv(dev);
+	priv->rx_int_enabled = enable;
+}
+/*
+ * Open and close
+ */
+
+int mpls_tunnel_open(struct net_device *dev)
+{
+	/* request_region(), request_irq(), ....  (like fops->open) */
+	netif_start_queue(dev);
+	return 0;
+}
+int mpls_release(struct net_device *dev)
+{
+    /* release ports, irq and such -- like fops->close */
+
+	netif_stop_queue(dev); /* can't transmit any more */
+	return 0;
+}
+
+/*
+ * Receive a packet: retrieve, encapsulate and pass over to upper levels
+ */
+void mpls_rx(struct net_device *dev, struct mpls_packet *pkt)
+{
+	struct sk_buff *skb;
+	struct mpls_tunnel_private *priv = netdev_priv(dev);
+
+	/*
+	 * The packet has been retrieved from the transmission
+	 * medium. Build an skb around it, so upper layers can handle it
+	 */
+	skb = dev_alloc_skb(pkt->datalen + 2);
+	if (!skb) {
+		if (printk_ratelimit())
+			printk(KERN_NOTICE "mpls rx: low on mem - packet dropped\n");
+		priv->stat.rx_dropped++;
+		goto out;
+	}
+	skb_reserve(skb, 2); /* align IP on 16B boundary */  
+	memcpy(skb_put(skb, pkt->datalen), pkt->data, pkt->datalen);
+
+	/* Write metadata, and then pass to the receive level */
+	skb->dev = dev;
+	skb->protocol = eth_type_trans(skb, dev);
+	skb->ip_summed = CHECKSUM_UNNECESSARY; /* don't check it */
+	priv->stat.rx_packets++;
+	priv->stat.rx_bytes += pkt->datalen;
+	netif_rx(skb);
+out:
+	return;
+}
+
+
+/*
+ * The poll implementation.
+ */
+/* 
+static int mpls_poll(struct net_device *dev, int *budget)
+{
+	int npackets = 0, quota = min(dev->quota, *budget);
+	struct sk_buff *skb;
+	struct mpls_tunnel_private *priv = netdev_priv(dev);
+	struct mpls_packet *pkt;
+    
+	while (npackets < quota && priv->rx_queue) {
+		pkt = mpls_dequeue_buf(dev);
+		skb = dev_alloc_skb(pkt->datalen + 2);
+		if (! skb) {
+			if (printk_ratelimit())
+				printk(KERN_NOTICE "mpls: packet dropped\n");
+			priv->stat.rx_dropped++;
+			mpls_release_buffer(pkt);
+			continue;
+		}
+		skb_reserve(skb, 2); *//* align IP on 16B boundary */  
+	/*	memcpy(skb_put(skb, pkt->datalen), pkt->data, pkt->datalen);
+		skb->dev = dev;
+		skb->protocol = eth_type_trans(skb, dev);
+		skb->ip_summed = CHECKSUM_UNNECESSARY; *//* don't check it */
+	//	netif_receive_skb(skb);
+		
+        	/* Maintain stats */
+		/*npackets++;
+		priv->stat.rx_packets++;
+		priv->stat.rx_bytes += pkt->datalen;
+		mpls_release_buffer(pkt);
+	}*/
+	/* If we processed all packets, we're done; tell the kernel and reenable ints */
+/*	*budget -= npackets;
+	dev->quota -= npackets;
+	if (! priv->rx_queue) {
+		netif_rx_complete(dev);
+		mpls_rx_ints(dev, 1);
+		return 0;
+	}*/
+	/* We couldn't process everything. */
+	/*return 1;
+}*/
+	    
+        
+/*
+ * The typical interrupt entry point
+ */
+//static void mpls_regular_interrupt(int irq, void *dev_id, struct pt_regs *regs)
+void mpls_regular_interrupt(int irq, void *dev_id, struct pt_regs *regs)
+{
+	int statusword;
+	struct mpls_tunnel_private *priv;
+	struct mpls_packet *pkt = NULL;
+	/*
+	 * As usual, check the "device" pointer to be sure it is
+	 * really interrupting.
+	 * Then assign "struct device *dev"
+	 */
+	struct net_device *dev = (struct net_device *)dev_id;
+	/* ... and check with hw if it's really ours */
+
+	/* paranoid */
+	if (!dev)
+		return;
+
+	/* Lock the device */
+	priv = netdev_priv(dev);
+	spin_lock(&priv->lock);
+
+	/* retrieve statusword: real netdevices use I/O instructions */
+	statusword = priv->status;
+	priv->status = 0;
+	if (statusword & MPLS_RX_INTR) {
+		/* send it to snull_rx for handling */
+		pkt = priv->rx_queue;
+		if (pkt) {
+			priv->rx_queue = pkt->next;
+			mpls_rx(dev, pkt);
+		}
+	}
+	if (statusword & MPLS_TX_INTR) {
+		/* a transmission is over: free the skb */
+		priv->stat.tx_packets++;
+		priv->stat.tx_bytes += priv->tx_packetlen;
+		dev_kfree_skb(priv->skb);
+	}
+
+	/* Unlock the device and we are done */
+	spin_unlock(&priv->lock);
+	if (pkt) mpls_release_buffer(pkt); /* Do this outside the lock! */
+	return;
+}
+
+/*
+ * A NAPI interrupt handler.
+ */
+//static void mpls_napi_interrupt(int irq, void *dev_id, struct pt_regs *regs)
+void mpls_napi_interrupt(int irq, void *dev_id, struct pt_regs *regs)
+{
+	int statusword;
+	struct mpls_tunnel_private *priv;
+
+	/*
+	 * As usual, check the "device" pointer for shared handlers.
+	 * Then assign "struct device *dev"
+	 */
+	struct net_device *dev = (struct net_device *)dev_id;
+	/* ... and check with hw if it's really ours */
+
+	/* paranoid */
+	if (!dev)
+		return;
+
+	/* Lock the device */
+	priv = netdev_priv(dev);
+	spin_lock(&priv->lock);
+
+	/* retrieve statusword: real netdevices use I/O instructions */
+	statusword = priv->status;
+	priv->status = 0;
+	if (statusword & MPLS_RX_INTR) {
+		mpls_rx_ints(dev, 0);  /* Disable further interrupts */
+		//netif_rx_schedule(dev);
+		napi_schedule(&priv->napi);
+	}
+	if (statusword & MPLS_TX_INTR) {
+        	/* a transmission is over: free the skb */
+		priv->stat.tx_packets++;
+		priv->stat.tx_bytes += priv->tx_packetlen;
+		dev_kfree_skb(priv->skb);
+	}
+
+	/* Unlock the device and we are done */
+	spin_unlock(&priv->lock);
+	return;
+}
+
+void mpls_hw_re_tx(char *buf, int len, struct net_device *dev){
+	/*
+	 * This function deals with hw details. This interface loops
+	 * back the packet to the other snull interface (if any).
+	 * In other words, this function implements the snull behaviour,
+	 * while all other procedures are rather device-independent
+	 */
+	struct mpls_tunnel_private *priv;
+	struct mpls_packet *tx_buffer;
+	/* I am paranoid. Ain't I? */
+	if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
+		printk("mpls tunnel : Hmm... packet too short (%i octets)\n",
+				len);
+		return;
+	}
+
+	/*
+	 * Ok, now the packet is ready for transmission: first simulate a
+	 * receive interrupt on the twin device, then  a
+	 * transmission-done on the transmitting device
+	 */
+	priv = netdev_priv(dev);
+	tx_buffer = mpls_get_tx_buffer(dev);
+	tx_buffer->datalen = len;
+	memcpy(tx_buffer->data, buf, len);
+	mpls_enqueue_buf(dev, tx_buffer);
+	if (priv->rx_int_enabled) {
+		priv->status |= MPLS_RX_INTR;
+		mpls_interrupt(0, dev, NULL);
+	}
+
+	priv = netdev_priv(dev);
+	priv->tx_packetlen = len;
+	priv->tx_packetdata = buf;
+	priv->status |= MPLS_TX_INTR;
+	if (lockup && ((priv->stat.tx_packets + 1) % lockup) == 0) {
+        	/* Simulate a dropped transmit interrupt */
+		netif_stop_queue(dev);
+	}
+	else
+		mpls_interrupt(0, dev, NULL);
+}
+
+int mpls_re_tx(struct sk_buff *skb, struct net_device *dev){
+	
+	int len;
+	char *data, shortpkt[ETH_ZLEN];
+	struct mpls_tunnel_private *priv = netdev_priv(dev);
+	data = skb->data;
+	len = skb->len;
+	if (len < ETH_ZLEN) {
+		memset(shortpkt, 0, ETH_ZLEN);
+		memcpy(shortpkt, skb->data, skb->len);
+		len = ETH_ZLEN;
+		data = shortpkt;
+	}
+	dev->trans_start = jiffies; /* save the timestamp */
+
+	/* Remember the skb, so we can free it at interrupt time */
+	priv->skb = skb;
+
+	/* actual deliver of data is device-specific, and not shown here */
+	mpls_hw_re_tx(data, len, dev); //re-transmit 
+	return 0; /* Our simple device can not fail */
+}
+
+/*
+ * Deal with a transmit timeout.
+ */
+void mpls_tx_timeout (struct net_device *dev)
+{
+	struct mpls_tunnel_private *priv = netdev_priv(dev);
+
+	//PDEBUG("Transmit timeout at %ld, latency %ld\n", jiffies,
+	//		jiffies - dev->trans_start);
+        /* Simulate a transmission interrupt to get things moving */
+	priv->status = MPLS_TX_INTR;
+	mpls_interrupt(0, dev, NULL);
+	priv->stat.tx_errors++;
+	netif_wake_queue(dev);
+	return;
+}
+
+//end receive code   
+
+/**
+ *	mpls_tunnel_set_nhlfe - sets the nhlfe for this virtual device.
+ *	@dev: netdevice "mpls%d" 
+ *	@key: nhlfe key. 
+ *
+ *	Sets the NHLFE for this mpls net_device according to the key: if the
+ *	key is zero, this function releases and resets the tunnel's nhlfe.
+ *	Otherwise, it holds a reference to the new nhlfe (as per key),
+ *	updates the MTU
+ *
+ *	The mtp_nhlfe member of the tunnel private structure holds a
+ *	reference to the new NHLFE object.
+ *	Returns 0 if ok.
+ *
+ *	Remarks:
+ *	     o This function increases the reference count of the NHLFE
+ *	       determined by the key if the key is non zero, since the
+ *	       NHLFE will be held by the device private part.
+ *	Changes:
+ *	     o RCAS 20040207. Use dev_set_mtu
+ **/
+
+static int mpls_tunnel_set_nhlfe (struct net_device* dev, unsigned int key) 
+{
+	struct mpls_nhlfe *nhlfe = NULL;
+	struct mpls_nhlfe *newnhlfe = NULL;
+	struct mpls_tunnel_private *priv = netdev_priv(dev);
+
+	MPLS_ENTER;
+
+	/* Get previous NHLFE (it is held by mtp)  */ 
+	nhlfe = priv->mtp_nhlfe;
+
+	/* If key is zero, the nhlfe for tunnel is reset, we are done */ 
+	if (!key) {
+		if (nhlfe) {
+			MPLS_DEBUG("dropping old nhlfe %x\n", nhlfe->nhlfe_key);
+			mpls_nhlfe_release(nhlfe);
+		}
+		MPLS_DEBUG("reset nhlfe %x\n", key);
+		priv->mtp_nhlfe = NULL;
+		dev->iflink = 0;
+		MPLS_EXIT;
+		return 0; 
+	}
+
+	/* Get a reference for new NHLFE */
+	newnhlfe = mpls_get_nhlfe(key);
+	if (unlikely(!newnhlfe)) {
+		MPLS_DEBUG("error fetching new nhlfe with key %u\n",key);
+		MPLS_DEBUG("keeping old nhlfe %x\n", nhlfe->nhlfe_key);
+		MPLS_EXIT;
+		return -ESRCH;
+	}
+
+	/* Drop old NHLFE */
+	if (nhlfe) {
+		dev_close(dev);
+		MPLS_DEBUG("dropping old nhlfe %x\n", nhlfe->nhlfe_key);
+		mpls_nhlfe_release(nhlfe);
+	}
+
+	/* Commit Set new NHLFE (it is held by mtp)  */ 
+ 	priv->mtp_nhlfe = newnhlfe;
+
+	if (newnhlfe) {
+		/* Set new MTU for the tunnel device */
+		dev_set_mtu(dev,newnhlfe->nhlfe_mtu);
+		dev_open(dev);
+	}
+
+	MPLS_EXIT;
+	return 0;
+}
+
+
+
+/**
+ *	mpls_tunnel_destructor - say tunnel goodbye.
+ *	@dev: mpls tunnel
+ *
+ *	This callback gets called when the core system destroys the net_device.
+ *	Remember that it was allocated with  alloc_netdev(netdev + privdata),
+ *	and dev->priv points to the "extension" (privdata). So we just reset to
+ *	NULL. cf. dev.c "It must be the very last action, after this 'dev' may
+ *	point to freed up memory.". the refcount of the object at this point is
+ *	zero.
+ *
+ *	Changes:
+ *	    20040118 RCAS: When destroying the tunnel, release the NHLFE
+ *	              object if it was there.
+ **/
+
+static void 
+mpls_tunnel_destructor (struct net_device *dev) 
+{
+	MPLS_ENTER;
+	mpls_tunnel_set_nhlfe (dev,0);
+	free_netdev (dev);
+	MPLS_EXIT;
+}
+
+
+
+
+/**
+ *	mpls_tunnel_xmit - transmit a socket buffer via the device.
+ *	@skb: data
+ *	@dev: mpls tunnel
+ *
+ *	This callback gets called when the core system wants to send a socket
+ *	buffer. the "mpls_output2" symbol will take care of it. This only
+ *	happens of course if someone set a valid NHLFE (e.g. PUSH/.../SET) for
+ *	the device
+ **/
+
+int 
+mpls_tunnel_xmit (struct sk_buff *skb, struct net_device *dev) 
+{
+	const char *err_nonhlfe = "NHLFE was invalid";
+	int result = 0;
+	struct mpls_tunnel_private *priv = netdev_priv(dev);
+	struct dst_entry *dst = (struct dst_entry*)skb->_skb_refdst;
+	
+	MPLS_ENTER;
+	MPLSCB(skb)->label = 0;
+	MPLSCB(skb)->ttl = 255;
+	MPLSCB(skb)->exp = 0;
+	MPLSCB(skb)->bos = (skb->protocol == htons(ETH_P_MPLS_UC)) ? 0 : 1;
+	MPLSCB(skb)->flag = 0;
+	MPLSCB(skb)->popped_bos = (MPLSCB(skb)->bos) ? 0 : 1;
+
+	dev->trans_start = jiffies;
+	if (priv->mtp_nhlfe) {
+		MPLS_DEBUG(
+		"Skb to Send\n"
+		"Device %s \n"
+		"DST %p\n"
+		"Protocol ID %04x\n",
+		skb->dev? skb->dev->name : "<>",
+		dst ? dst : NULL,
+		ntohs(skb->protocol)
+		);
+			
+		MPLS_DEBUG("Using NHLFE %08x\n", 
+			priv->mtp_nhlfe->nhlfe_key);
+		priv->stat.tx_packets++;
+		priv->stat.tx_bytes += skb->len;
+		MPLS_DEBUG_CALL(mpls_skb_dump(skb));
+		result = mpls_output2 (skb, priv->mtp_nhlfe);
+		MPLS_EXIT;
+		return result; 
+	}
+
+	dev_kfree_skb(skb);
+	priv->stat.tx_errors++;
+	MPLS_DEBUG("exit - %s\n", err_nonhlfe);
+	return 0;
+
+}
+
+
+
+/**
+ *	mpls_tunnel_get_stats - get sender statistics for this tunnel 
+ *	@dev: virtual "mpls%d" device.
+ **/
+
+static struct net_device_stats* 
+mpls_tunnel_get_stats (struct net_device *dev) 
+{
+	struct mpls_tunnel_private *priv = netdev_priv(dev);
+	return &(priv->stat);
+}
+
+
+
+
+/**
+ *	mpls_tunnel_change_mtu - Grant new MTU value for device. 
+ *	@dev: virtual "mpls%d" device.
+ *	@new_mtu: new value 
+ *
+ *	Called by dev_set_mtu (see net/code/dev.c). May veto the new value.
+ *	Returns 0 if Ok. -EINVAL otherwise. 
+ *	dev_set_mtu(dev,new) takes care of the actual assignement.
+ **/
+
+static int 
+mpls_tunnel_change_mtu (struct net_device *dev, int new_mtu) 
+{
+	struct mpls_tunnel_private *priv = netdev_priv(dev);
+
+	MPLS_ENTER;
+	if (new_mtu < 4 || new_mtu > priv->mtp_nhlfe->nhlfe_mtu)
+		return -EINVAL;
+	MPLS_EXIT;
+	return 0;
+}
+
+
+/**
+ *	mpls_tunnel_ioctl - callback for device private IOCTL calls
+ *	@dev: virtual "mpls%d" device.
+ *	@ifr: IOCTL request data
+ *	@cmd: IOCTL command
+ *
+ *	Called in response to a userland IOCTL call for configuring
+ *	this tunnel interface
+ *	Returns 0 if Ok. < 0 on error
+ **/
+
+static int mpls_tunnel_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
+{
+	int retval = -EINVAL;
+	struct mpls_tunnel_private *priv = netdev_priv(dev);
+
+	MPLS_ENTER;
+	switch (cmd) {
+	    /* set NHLFE */
+	    case SIOCDEVPRIVATE:
+		retval = mpls_tunnel_set_nhlfe(dev, ifr->ifr_ifru.ifru_ivalue);
+		break;
+	    /* get NHLFE */
+	    case SIOCDEVPRIVATE + 1:
+		if (priv->mtp_nhlfe) {
+			ifr->ifr_ifru.ifru_ivalue =
+				priv->mtp_nhlfe ?
+				priv->mtp_nhlfe->nhlfe_key : 0;
+			retval = 0;
+		}
+		break;
+	    /*create new tunnel interface*/
+	    case SIOCDEVPRIVATE + 2:
+		MPLS_DEBUG("Create new tunnel interface.\n");
+		break;
+	    default:
+		break;
+	}
+
+	MPLS_ENTER;
+	return retval;
+}
+
+
+/**
+ *	mpls_tunnel_setup - main setup callback
+ *	@dev - mpls%d
+ *
+ *	Main setup function. Called by net/core/dev.c after a successful
+ *	netdev_alloc. We just set the function pointer table, device type and
+ *	flags. Initial MTU value is arbitrary, since the tunnel hasn't a valid
+ *	NHLFE object (NHLFE objects know the number of pushes and the MTU of the
+ *	real physical device).
+ **/
+
+static const struct net_device_ops mpls_tunnel_ndo = {
+        .ndo_open = mpls_tunnel_open,
+	.ndo_stop = mpls_release,
+	.ndo_tx_timeout	= mpls_tx_timeout,
+	.ndo_init = NULL,
+	.ndo_uninit = NULL,
+        .ndo_do_ioctl = mpls_tunnel_ioctl,
+        .ndo_start_xmit = mpls_tunnel_xmit,
+        .ndo_get_stats = mpls_tunnel_get_stats,
+        .ndo_change_mtu = mpls_tunnel_change_mtu,
+};
+
+
+static void 
+mpls_tunnel_setup (struct net_device *dev) 
+{
+	struct mpls_tunnel_private *priv; //add by here
+	//SET_MODULE_OWNER(dev);
+	/* Callbacks */
+	dev->destructor      = mpls_tunnel_destructor;
+	dev->netdev_ops      = &mpls_tunnel_ndo;
+
+	/* Properties of mpls%d devices */
+	dev->type            = ARPHRD_MPLS_TUNNEL;
+	dev->hard_header_len = sizeof(u32);
+	dev->mtu	     = 1500;
+	dev->flags	     = IFF_NOARP|IFF_POINTOPOINT;
+	dev->iflink	     = 0;
+	dev->addr_len	     = 4;
+	/*
+	if (use_napi) {
+		dev->poll        = mpls_poll;
+		dev->weight      = 16; // 2-->16
+	}*/
+	
+	random_ether_addr(dev->dev_addr);
+	
+	/*
+	 * Then, initialize the priv field. This encloses the statistics
+	 * and a few private fields.
+	 */
+	priv = netdev_priv(dev);
+	memset(priv, 0, sizeof(struct mpls_tunnel_private));
+	spin_lock_init(&priv->lock);
+	mpls_rx_ints(dev, 1);		/* enable receive interrupts */
+	mpls_tunnel_setup_pool(dev);//add by here
+}
+
+static char mpls_tunnel_name[IFNAMSIZ + 1] = "mpls%d";
+//static int mplsnum = -1;
+
+//add by here for create the tunnel interface 
+static int 
+__mpls_tunnel_add (char *if_na)
+{
+//	struct mpls_interface *mpls_ptr = dev->mpls_ptr;
+	int retval = -EINVAL;
+	struct net_device          *dev = NULL; /* Created device */
+	struct mpls_tunnel_private *mtp = NULL; /* Priv Extension */
+	MPLS_ENTER;
+	//if (mplsnum != -1)
+	sprintf(mpls_tunnel_name,"%s",if_na);
+	/* Allocate the netdev */
+	dev = alloc_netdev (sizeof(struct mpls_tunnel_private),
+		mpls_tunnel_name, mpls_tunnel_setup);
+	if (unlikely(!dev))
+		goto err;
+
+	/* 
+	 * Register newly created net_device.
+	 * register_netdev will alloc a name for us if 
+	 * % is in the pattern.
+	 */
+
+	if (unlikely(register_netdev(dev))) {
+		free_netdev(dev);
+		goto err;
+	}
+
+	printk("Registered MPLS tunnel %s\n",dev->name);
+
+	/* Back reference to the netdevice */
+	mtp = netdev_priv(dev);
+	mtp->mtp_dev = dev;
+
+	strncpy(mpls_tunnel_name, dev->name, IFNAMSIZ);
+	//mpls_tunnel_event(MPLS_CMD_ADDTUNNEL,dev);
+	mpls_tunnel_event(MPLS_CMD_ADDTUNNEL);
+	MPLS_EXIT;
+	return 0;
+
+err:
+	mpls_tunnel_event(MPLS_CMD_ADDTUNNEL);
+	return retval;
+}
+
+static int 
+__mpls_tunnel_del (char *if_na)
+{
+	int retval = 0;
+
+	struct net_device *dev;
+	MPLS_ENTER;
+	sprintf(mpls_tunnel_name,"%s",if_na);
+	dev = __dev_get_by_name (&init_net, if_na);
+	//mpls_tunnel_destructor(dev);
+	if (likely(dev)) {
+		unregister_netdev(dev);
+		mpls_teardown_pool(dev); // add by here
+		//free_netdev(dev);// add by here ; need to check ??? due to kernel panic  
+	}
+	synchronize_net();
+	MPLS_EXIT;
+	mpls_tunnel_event(MPLS_CMD_DELTUNNEL);
+	return retval;
+}
+//end by here
+
+int 
+mpls_tunnel_add (struct mpls_tunnel_req  *req)
+{
+	int result = -EINVAL;
+	MPLS_ENTER;
+	result = __mpls_tunnel_add (req->mt_ifname);
+	/*
+	struct net_device *dev = __dev_get_by_name (req->mt_ifname);
+	if (dev) {
+		result = __mpls_tunnel_add (dev);
+		dev_put (dev);
+	}*/
+	MPLS_EXIT;
+	return result;
+}
+int 
+mpls_tunnel_del (struct mpls_tunnel_req  *req)
+{
+	int result = -EINVAL;
+	MPLS_ENTER;
+	result = __mpls_tunnel_del (req->mt_ifname);
+	/*
+	struct net_device *dev = __dev_get_by_name (req->mt_ifname);
+	if (dev) {
+		result = __mpls_tunnel_add (dev);
+		dev_put (dev);
+	}*/
+	MPLS_EXIT;
+	return result;
+}
+EXPORT_SYMBOL(mpls_re_tx);
+EXPORT_SYMBOL(mpls_regular_interrupt);
+EXPORT_SYMBOL(mpls_napi_interrupt);
+EXPORT_SYMBOL(mpls_tunnel_xmit);
