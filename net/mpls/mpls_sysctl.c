/*
 * sysctl_net_mpls.c: sysctl interface to net MPLS subsystem.
 */

#include <linux/mm.h>
#include <linux/sysctl.h>
#include <net/mpls.h>

static ctl_table mpls_table[] = {
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
};

static struct ctl_path mpls_path[] = {
	{ .procname = "net", },
	{ .procname = "mpls", },
	{ }
};

static struct ctl_table_header *mpls_table_header;

int __init mpls_sysctl_init(void)
{
	mpls_table_header = register_sysctl_paths(mpls_path, mpls_table);
	if (!mpls_table_header)
		return -ENOMEM;
	return 0;
}

void mpls_sysctl_exit(void)
{
	unregister_sysctl_table(mpls_table_header);
}
