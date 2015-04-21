#ifndef _XT_MPLS_H_target
#define _XT_MPLS_H_target

struct xt_mpls_target_info {
	u_int32_t key;

	/* only used by the netfilter kernel modules */
	void *nhlfe;
	void *proto;
};

#endif /*_XT_MPLS_H_target */
