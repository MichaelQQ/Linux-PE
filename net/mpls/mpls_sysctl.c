/*
 * sysctl_net_mpls.c: sysctl interface to net MPLS subsystem.
 */

#include <linux/mm.h>
#include <linux/sysctl.h>
#include <net/mpls.h>

static struct ctl_table mpls_table_template[] = {
	{
		.procname	= "debug",
		.data		= &sysctl_mpls_debug,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{
		.procname	= "default_ttl",
		.data		= &sysctl_mpls_default_ttl,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{ }
};

/*static int __net_init mpls_sysctl_net_init(struct net *net)
{
	struct ctl_table *mpls_table;
	int err;

	err = -ENOMEM;
	mpls_table = kmemdup(mpls_table_template, sizeof(mpls_table_template),
			GEP_KERNEL);
	
	if(!mpls_table)
		goto out;
	mpls_table[0].data = &net->mpls.sysctl.debug;
	mpls_table[1].data = &net->mpls.sysctl.default_ttl;

	net->mpls.sysctl.hdr = register_net_sysctl(net, "net/mpls", mpls_table);
	if(!net->mpls.sysctl.hdr)
		goto out_mpls_table;
	
	err = 0;
out:
	return err;
out_mpls_table:
	kfree(mpls_table);
	goto out;
}

static void __net_exit mpls_sysctl_net_exit(struct net *net)
{
	struct ctl_table *mpls_table;

	mpls_table = net->mpls.sysctl.hdr->ctl_table_arg;

	unregister_net_sysctl_table(net->mpls.sysctl.hdr);

	kfree(mpls_table);
}

static struct pernet_operations mpls_sysctl_net_ops = {
	.init = mpls_sysctl_net_init,
	.exit = mpls_sysctl_net_exit,
};

static struct ctl_table_header *mpls_table_header;

int mpls_sysctl_register(void)
{
	int err = -ENOMEM;

	//mpls_table_header = register_net_sysctl(&init_net, "net/mpls", mpls_table)

	err = register_pernet_sysctl(&mpls_sysctl_net_ops);
	if(err)
		goto err_pernet;
}

void mpls_sysctl_unregister(void)
{
	unregister_pernet_subsys(&mpls_sysctl_net_ops);
}
*/

static struct ctl_table_header *mpls_table_header;

int __init mpls_sysctl_init(void)
{
	mpls_table_header = register_net_sysctl(&init_net, "net/mpls", mpls_table_header);
	if (!mpls_table_header)
		return -ENOMEM;
	return 0;
}

void mpls_sysctl_exit(void)
{
	unregister_sysctl_table(mpls_table_header);
}
