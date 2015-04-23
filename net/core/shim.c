/*
 *      Network shim interface for protocols that live below L3 and above L2
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 *	Heavily borrowed from dev_remove_pack/dev_add_pack
 *
 *	Authors:	James R. Leu <jleu@mindspring.com>
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <asm/byteorder.h>
#include <linux/list.h>
#include <net/shim.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

spinlock_t shim_proto_lock = __SPIN_LOCK_UNLOCKED(shim_proto_lock);
struct list_head shim_proto_list;

/**
 *	shim_proto_add - add a shim protocol handler
 *	@shim: shim declaration
 *
 * 	Add a shim protocol handler to the networking stack.  The
 *	passed &shim is linked into the kernel list and may not be
 *	freed until it has been removed from the kernel list.
 *
 *	This call does not sleep therefore is can not guarantee all
 *	CPU's that are in middle of processing packets will see the
 *	new shim handler (until they process another packet)
 */

void shim_proto_add(struct shim *shim)
{
	spin_lock_bh(&shim_proto_lock);

	atomic_set(&shim->refcnt, 1);
	list_add_rcu(&shim->list, &shim_proto_list);

	spin_unlock_bh(&shim_proto_lock);
}

/**
 *	shim_proto_remove - remove a shim protocol handler
 *	@shim: shim declaration
 *
 *	Remove a shim handler that was previously added to the
 *	kernels list of shim handlers by shim_proto_add().  The
 *	pass &shim is removed from the kernels list and can be freed
 *	or reused once this function returns.
 *
 *	This call sleeps to guarantee that no CPU is looking at the
 *	special nexthop handler after return.
 */

int shim_proto_remove(struct shim *shim)
{
	struct shim *shim1;
	int retval = -EPROTONOSUPPORT;

	spin_lock_bh(&shim_proto_lock);

	list_for_each_entry(shim1, &shim_proto_list, list) {
		if (shim == shim1) {
			if (atomic_read(&shim->refcnt) != 1) {
				retval = -EADDRINUSE;
			} else {
				list_del_rcu(&shim->list);
				retval = 0;
			}
			break;
		}
	}
	spin_unlock_bh(&shim_proto_lock);

	synchronize_net();
	return retval;
}

/**
 *	shim_proto_find_by_name - find a shim handler by it's registered name
 *	@name: protocol name
 *
 *	Search the kernels list of shim handlers looking for
 *	a handler with this specific name
 */
struct shim *shim_proto_find_by_name(const char *name)
{
	struct shim *shim;

	spin_lock_bh(&shim_proto_lock);

	list_for_each_entry(shim, &shim_proto_list, list) {
		if (!strncmp(name, shim->name, SHIMNAMSIZ)) {
			shim_proto_hold(shim);
			goto out;
		}
	}
	shim = NULL;
out:
	spin_unlock_bh(&shim_proto_lock);

	return shim;
}

/*
 * Shim block utilities
 */

/**
 *	shim_build_blk - allocate memory for a shim blk and fill it with data
 *			 from rta
 *	@rta: data describing shim
 *
 *	Allocate a shim blk which links directly to the shim
 *	proto for use by the forwarding plane
 */
struct shim_blk *shim_build_blk(struct rtshim* rta)
{
	struct shim_blk *sblk;

	if (!rta)
		return NULL;

	sblk = kmalloc(sizeof(*sblk) + rta->datalen, GFP_ATOMIC);
	if (sblk) {
		sblk->shim = shim_proto_find_by_name(rta->name);
		if (sblk->shim) {
			sblk->datalen = rta->datalen;
			memcpy(sblk->data, rta->data, rta->datalen);
			return sblk;
		}
		kfree (sblk);
	}
	return NULL;
}

/**
 *	shim_destroy_blk - free memory a refcnts used bt a shim blk
 *	@sblk: shim blk
 *
 *	Release ref to shim proto and free memory
 */
void shim_destroy_blk(struct shim_blk *sblk)
{
	shim_proto_release(sblk->shim);
	kfree(sblk);
}

/**
 *	shim_unbuild_blk - copy data from various parts of a shim block
 *			   into a form which can be used by netlink
 *	@rta: contigous destination memory of size rtshim + datalen
 *	@sblk: active shim blk
 *
 *	Search the kernels list of shim handlers looking for
 *	a handler with this specific name
 */
void shim_unbuild_blk(struct rtshim* rta, struct shim_blk *sblk)
{
	rta->datalen = sblk->datalen;
	memcpy(rta->data, sblk->data, sblk->datalen);
	strncpy(rta->name, sblk->shim->name, SHIMNAMSIZ);
}

/**
 *	shim_rta_blk_cmp - compare config info with an active shim blk
 *	@rta: config data
 *	@sblk: shim blk
 *
 *	Used for comparing new config data with existing shim blks
 */
int shim_cfg_blk_cmp(struct rtshim *a, struct shim_blk *b)
{
	int n = 0;
	if (a && b) {
		if (!(n = strncmp(a->name, b->shim->name, SHIMNAMSIZ)))
		    n = memcmp(a->data, b->data, a->datalen);
	} else {
		if (a) n = 1;
		if (b) n = -1;
	}
	return n;
}

/**
 *	shim_blk_cmp - compare two active shim blks
 *	@a: shim blk
 *	@b: shim blk
 *
 *	Used for comparing two existing shim blks
 */
int shim_blk_cmp(struct shim_blk *a, struct shim_blk *b)
{
	int n = 0;
	if (a && b) {
		if (!(n = strncmp(a->shim->name, b->shim->name, SHIMNAMSIZ)))
		    n = memcmp(a->data, b->data, a->datalen);
	} else {
		if (a) n = 1;
		if (b) n = -1;
	}
	return n;
}

#ifdef CONFIG_PROC_FS
static struct shim *shim_skip(struct shim *shim)
{
	struct shim *shim1;
	int next = 0;

	if (!shim)
		next = 1;
		
	list_for_each_entry(shim1, &shim_proto_list, list) {
		if (next)
			return shim1;

		if (shim1 == shim)
			next = 1;
	}

	return NULL;
}

static void *shim_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct shim *shim;
	loff_t i = 1;

	spin_lock_bh(&shim_proto_lock);

	if (*pos == 0)
		return SEQ_START_TOKEN;

	for (shim = shim_skip(NULL); shim && i < *pos;
		shim = shim_skip(shim), ++i);
										
	return (i == *pos) ? shim : NULL;
}

static void *shim_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	++*pos;
										
	return shim_skip((v == SEQ_START_TOKEN)
			    ? NULL
			    : (struct shim *)v);
}
										
static void shim_seq_stop(struct seq_file *seq, void *v)
{
	spin_unlock_bh(&shim_proto_lock);
}

static int shim_seq_show(struct seq_file *seq, void *v)
{
	struct shim* shim = (struct shim*)v;
	if (v != SEQ_START_TOKEN)
		seq_printf(seq, "%s\t%d\n",
		    shim->name ? shim->name : "(none)",
		    atomic_read(&shim->refcnt));
	return 0;
}

static struct seq_operations shim_seq_ops = {
	.start = shim_seq_start,
	.next = shim_seq_next,
	.stop = shim_seq_stop,
	.show = shim_seq_show,
};
										
static int shim_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &shim_seq_ops);
}
										
static struct file_operations shim_seq_fops = {
	.owner   = THIS_MODULE,
	.open    = shim_seq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

static int __net_init shim_proc_net_init(struct net *net)
{
	if (!proc_create("shim",  S_IRUGO, net->proc_net, &shim_seq_fops))
	    return -ENOMEM;
	return 0;
}

static void __net_exit shim_proc_net_exit(struct net *net)
{
	remove_proc_entry("shim", net->proc_net);
}

static struct pernet_operations __net_initdata shim_proc_ops = {
	.init = shim_proc_net_init,
	.exit = shim_proc_net_exit,
};

static int __init shim_proc_init(void)
{
	return register_pernet_subsys(&shim_proc_ops);
}
#else
#define shim_proc_init() 0
#endif

static int __init shim_init(void)
{
	printk("NET: shim interface - <jleu@mindspring.com>\n");
	INIT_LIST_HEAD(&shim_proto_list);
	if (shim_proc_init())
	    return -ENOMEM;
	return 0;
}

subsys_initcall(shim_init);

EXPORT_SYMBOL(shim_proto_add);
EXPORT_SYMBOL(shim_proto_remove);
EXPORT_SYMBOL(shim_build_blk);
EXPORT_SYMBOL(shim_destroy_blk);
