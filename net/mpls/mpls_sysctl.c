-- mpls-linux-2.6.35.y/net/mpls/mpls_sysctl.c	1970-01-01 08:00:00.000000000 +0800
++ linux-2.6.35-vpls/net/mpls/mpls_sysctl.c	2015-04-20 20:24:43.759583630 +0800
@ -0,0 +1,45 @@
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
