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
 * 20031126 RCAS 
 *      - Split netdev_event callback. 
 * 20040116 RCAS 
 *      - Error Checking in init function 
 * 20040127 RCAS 
 *      - If a down interface was referenced by a ILM/NHLFE, destroy ILM/NHLFE
 *	instructions if interface goes down/unregged.
 * 20050829 JLEU
 *	- move to shim interface
 * 20051206 JLEU
 *	- move shim code to seperate file
 ****************************************************************************/

#include <generated/autoconf.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <net/dst.h>
#include <net/mpls.h>

/**
 * MODULE Information and attributes
 *
 **/

MODULE_AUTHOR("James R. Leu <jleu@mindspring.com>, Ramon Casellas <casellas@infres.enst.fr>");
MODULE_DESCRIPTION("MultiProtocol Label Switching protocol");
MODULE_LICENSE("GPL");
#if 0
MODULE_ALIAS_NETPROTO(PF_MPLS);
#endif

/*****
 * Packet Type for MPLS Unicast Traffic register info.
 *
 **/

static struct packet_type mpls_uc_packet_type = {
	.type = __constant_htons(ETH_P_MPLS_UC), /* MPLS Unicast PID */
	.dev  = NULL,                            /* All devices */
	.func = mpls_skb_recv,
};

/*****
 * Packet Type for MPLS Multicast Traffic register info.
 *
 **/

static struct packet_type mpls_mc_packet_type = {
	.type = __constant_htons(ETH_P_MPLS_MC),
	.dev  = NULL,
	.func = mpls_skb_recv_mc, /* MPLS multicast receive method */
};

/**
 *	mpls_release_netdev_in_nhlfe - Release the held device if it goes down.
 *	@dev: network device (for which the notification is sent).
 *
 *	NHLFE objects hold a reference to the used outgoing device in the SET op
 *	data. When the MPLS subsystem is notified that a device is going down
 *	or unregistered, this function destroys the instructions for those NHLFE
 **/

static int 
mpls_release_netdev_in_nhlfe (struct mpls_interface *mif)
{
	struct mpls_nhlfe	*holder = NULL;
	struct list_head        *pos    = NULL;
	struct list_head        *tmp    = NULL;

	/* Iterate all NHLFE objects present in the list_out of the interface.*/
	list_for_each_safe(pos,tmp,&mif->list_out) {

		/* Get the holder / owner NHLFE */ 
		holder = list_entry(pos,struct mpls_nhlfe ,dev_entry);

		/* Destroy the instruction list */
		mpls_destroy_out_instrs(holder);
	}
	return NOTIFY_DONE;
}



/**
 *	mpls_release_netdev_in_ilm - Release the held device if it goes down.
 *	@dev: network device (for which the notification is sent).
 *
 *	ILM objects hold a reference to the 'faked' incoming device (SET_RX op)
 *	data. When the MPLS subsystem is notified that a device is going down
 *	or unregistered, this function destroys the instructions for those ILM 
 **/

static int 
mpls_release_netdev_in_ilm (struct mpls_interface *mif)
{
	struct mpls_ilm         *holder = NULL;
	struct list_head        *pos    = NULL;
	struct list_head        *tmp    = NULL;

	/* Iterate all ILM objects present in the list_in of the interface.*/
	list_for_each_safe(pos,tmp,&mif->list_in) {
		holder = list_entry(pos, struct mpls_ilm,dev_entry);

		/* Destroy the instruction list */
		mpls_destroy_in_instrs(holder);
	}
	return NOTIFY_DONE;
}

/**
 *	mpls_netdev_event - Netdevice notifier callback.
 *	@this: block notifier used.
 *	@event:  UP/DOWN, REGISTER/UNREGISTER... 
 *	@ptr: (struct net_device*)
 *	Receives events for the interfaces
 *
 *	RCAS 20031126: 
 *		o Split
 **/

static int 
mpls_netdev_event (struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev = ptr;
	struct mpls_interface *mif = mpls_get_if_info(dev->ifindex);
	if (!mif)
		return NOTIFY_DONE;

	/*
	 * Only continue for MPLS enabled interfaces 
	 */
	if (!mif) 
		return NOTIFY_DONE;

	switch (event) {
		case NETDEV_UNREGISTER:
			mpls_release_netdev_in_nhlfe(mif);
			mpls_release_netdev_in_ilm(mif);
			break;
		case NETDEV_DOWN:
		case NETDEV_CHANGEMTU:
		case NETDEV_UP:
		case NETDEV_CHANGE:
			break;
	}
	return NOTIFY_DONE;
}

/** 
 * Netdevice notifier callback register info
 *
 **/
static struct notifier_block mpls_netdev_notifier = {
	.notifier_call =  mpls_netdev_event,
};

/**
 * MPLS Module entry point.
 **/

static int __init 
mpls_init_module (void) 
{
	int err;
	printk(MPLS_INF "MPLS: version %d.%d%d%d\n",
			(MPLS_LINUX_VERSION >> 24) & 0xFF,
			(MPLS_LINUX_VERSION >> 16) & 0xFF,
			(MPLS_LINUX_VERSION >> 8) & 0xFF,
			(MPLS_LINUX_VERSION) & 0xFF);

	/* Init Input Radix Tree */
	if ((err = mpls_ilm_init()))
		return err;
	/* Init Output Radix Tree */
	if ((err = mpls_nhlfe_init()))
		return err;
	// Init MPLS Destination Cache Management 
	if ((err = mpls_dst_init()))
		return err;
/*#ifdef CONFIG_PROC_FS
	// MPLS ProcFS Subsystem 
	if ((err = mpls_procfs_init()))
		return err;
#endif
#ifdef CONFIG_SYSCTL
	if ((err = mpls_sysctl_init()))
		return err;
#endif*/
	// Netlink configuration interface 
	if ((err = mpls_netlink_init()))
		return err;

	// register shim protocol 
	mpls_shim_init();

	// Layer 3 protocol driver initialization 
	mpls_proto_init();

	// packet handlers, and netdev notifier 
	dev_add_pack(&mpls_uc_packet_type);
	dev_add_pack(&mpls_mc_packet_type);
	register_netdevice_notifier(&mpls_netdev_notifier);

	// add by here 
	mpls_interrupt =  mpls_regular_interrupt;
	
	printk("MPLS init done!!");

	return 0;
}

/**
 *	mpls_exit_module - Module Exit Cleanup Routine
 *
 *	mpls_exit_module is called just before the module is removed
 *	from memory.
 **/

static void __exit 
mpls_exit_module (void)
{
	unregister_netdevice_notifier(&mpls_netdev_notifier);
	dev_remove_pack(&mpls_mc_packet_type);
	dev_remove_pack(&mpls_uc_packet_type);
	mpls_shim_exit();
	mpls_proto_exit();
	mpls_netlink_exit();
/*#ifdef CONFIG_SYSCTL
	mpls_sysctl_exit();
#endif
#ifdef CONFIG_PROC_FS
	mpls_procfs_exit();
#endif*/
	mpls_dst_exit();
	mpls_nhlfe_exit();
	mpls_ilm_exit();

	synchronize_net();

	printk("MPLS: version %d.%d%d%d exiting\n",
		(MPLS_LINUX_VERSION >> 24) & 0xFF,
		(MPLS_LINUX_VERSION >> 16) & 0xFF,
		(MPLS_LINUX_VERSION >> 8) & 0xFF,
		(MPLS_LINUX_VERSION & 0xFF));
}

/**
 *
 * variables controled via sysctl
 *
 **/
int sysctl_mpls_debug = 0;
int sysctl_mpls_default_ttl = 255;

module_init(mpls_init_module);
module_exit(mpls_exit_module);

EXPORT_SYMBOL(sysctl_mpls_debug);
EXPORT_SYMBOL(sysctl_mpls_default_ttl);
