/*****************************************************************************
 * MPLS
 *      An implementation of the MPLS (MultiProtocol Label
 *      Switching Architecture) for Linux.
 *
 * File:  linux/include/net/mpls.h
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
 *   Changes:
 *   20031126 RCAS:
 *         - Rewrite the debugging macros.
 *   20040319 JLEU:
 *	   - switch to gen_stats
 *   20041018 JLEU
 *	   - added cache_flush to the prot driver
 *****************************************************************************
 */
#ifndef __LINUX_NET_MPLS__H_
#define __LINUX_NET_MPLS__H_

#include <generated/autoconf.h>
#include <net/shim.h>
#include <net/dst.h>
#include <asm/atomic.h>
#include <linux/init.h>
#include <linux/mpls.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/gen_stats.h>
#include <linux/sysctl.h>

/* 
 * Forward declarations
 */

struct fib_result;
struct rtable;

extern int sysctl_mpls_debug;
extern int sysctl_mpls_default_ttl;
extern struct dst_ops mpls_dst_ops;

#define MPLS_ERR KERN_ERR
#define MPLS_INF KERN_ALERT
#define MPLS_DBG KERN_DEBUG

/* Comment this to suppress MPLS_DEBUG calls */
#define MPLS_ENABLE_DEBUG 1

/* Comment this to suppress TRACING enter/exit functions */
#define MPLS_ENABLE_DEBUG_FUNC 1

#ifdef  MPLS_ENABLE_DEBUG
#define MPLS_DEBUG(f, a...) \
{ \
	if (sysctl_mpls_debug) {\
		printk (MPLS_DBG "MPLS DEBUG %s:%d:%s: ", \
			__FILE__, __LINE__, __FUNCTION__); \
		printk (f, ##a); \
	}\
}

#define MPLS_DEBUG_CALL(f) \
{ \
	if (sysctl_mpls_debug) {\
		f; \
	} \
}
#else
#define MPLS_DEBUG(f, a...) /**/
#define MPLS_DEBUG_CALL(f) /**/
#endif /* MPLS_ENABLE_DEBUG */

#ifdef MPLS_ENABLE_DEBUG_FUNC
#define MPLS_ENTER MPLS_DEBUG("enter\n")
#define MPLS_EXIT  MPLS_DEBUG("exit\n")
#else
#define MPLS_ENTER /**/
#define MPLS_EXIT  /**/
#endif

#define MPLS_INFO(f, a...) printk (KERN_INFO "MPLS INFO " f, ##a);

#ifdef MPLS_ENABLE_DEBUG 
#define MPLS_ASSERT(expr) \
if(unlikely(!(expr))) { \
	printk(KERN_ERR "MPLS Assertion failed! %s,%s,%s,line=%d\n",#expr,\
	__FILE__,__FUNCTION__,__LINE__);          \
}
#else
#define MPLS_ASSERT(expr) /**/
#endif /* MPLS_ENABLE_DEBUG */

/****************************************************************************
 * MPLS Interface "Extension" 
 * In the current implementation the "all loved" net_device struct is 
 * extended with one field struct mpls_interface (cast'd to void) called
 * mpls_ptr; This holds basically the "per interface" labelspace.
 ****************************************************************************/

struct mpls_interface {
	/*  
	 * (any mif object)->list_out is a circular d-linked list. Each node
	 * of this list is a NHLFE. NHLFE's are added to this list when adding a 
	 * OP_SET opcode to a nhlfe instruction array.
	 * 
	 * list_add(&nhlfe->dev_entry, &mpls_if->list_out) : adds nhlfe to this 
	 * list.
	 *
	 * "List of all NHLFEs that use this device (e.g. eth0) as output"
	 * cf. mpls_init.c
	 */
	struct list_head list_out;
	                         

	/*  
	 * (any mif object)->list_in is a circular d-linked list. Each node
	 * of this list is a ILM. ILM's are added to this list when 
	 */
	struct list_head list_in;  

	/* 
	 * Label Space for this interface 
	 */
	int  labelspace;  
};



extern struct mpls_interface* mpls_create_if_info(void);
extern void                   mpls_delete_if_info(struct net_device *);
extern struct mpls_interface* mpls_get_if_info(unsigned int);

/****************************************************************************
 * Socket Buffer Mangement
 ****************************************************************************/

struct mpls_skb_parm {
	struct mpls_prot_driver *prot;
	unsigned int  gap;
	unsigned int  label:20;
	unsigned int  ttl:8;
	unsigned int  exp:3;
	unsigned int  bos:1;
	unsigned char flag;
	unsigned char popped_bos;
	unsigned char *top_of_stack;
};

#define MPLSCB(skb) ((struct mpls_skb_parm*)((skb)->cb))


/****************************************************************************
 * Result codes for Input/Output Opcodes. 
 * net/mpls/{mpls_opcode,mpls_opcode_all}.c
 ****************************************************************************/

#define MPLS_RESULT_SUCCESS	0
#define MPLS_RESULT_RECURSE	1
#define MPLS_RESULT_DROP	2
#define MPLS_RESULT_DLV		3
#define MPLS_RESULT_FWD		4


/**
 * mpls_instr - Struct to hold one instruction
 * @mi_opcode: Opcode. MPLS_OP_POP,etc...       
 * @mi_data:   Opcode data.
 * @mi_next:   Next Instruction to execute. 
 **/
struct mpls_instr {
	struct mpls_instr  *mi_next;
	unsigned short      mi_opcode;
	enum mpls_dir       mi_dir;
	void               *mi_data; 
	void *              mi_parent;
};


struct mpls_nfmark_fwd_info {
	struct mpls_nhlfe *nfi_nhlfe[MPLS_NFMARK_NUM];
	unsigned short        nfi_mask;
};

struct mpls_dsmark_fwd_info {
	struct mpls_nhlfe *dfi_nhlfe[MPLS_DSMARK_NUM];
	unsigned char         dfi_mask;
};

struct mpls_tcindex_fwd_info {
	struct mpls_nhlfe *tfi_nhlfe[MPLS_TCINDEX_NUM];
	unsigned short        tfi_mask;
};

struct mpls_exp_fwd_info {
	struct mpls_nhlfe *efi_nhlfe[MPLS_EXP_NUM];
};

struct mpls_exp2dsmark_info {
	unsigned char e2d[MPLS_EXP_NUM];
};

struct mpls_exp2tcindex_info {
	unsigned short e2t[MPLS_EXP_NUM];
};

struct mpls_tcindex2exp_info {
	unsigned char t2e_mask;
	unsigned char t2e[MPLS_TCINDEX_NUM];
};

struct mpls_dsmark2exp_info {
	unsigned char d2e_mask;
	unsigned char d2e[MPLS_DSMARK_NUM];
};

struct mpls_nfmark2exp_info {
	unsigned char n2e_mask;
	unsigned char n2e[MPLS_NFMARK_NUM];
};

/****************************************************************************
 * Instruction (OPCODEs) Management 
 * net/mpls/mpls_instr.c
 ****************************************************************************/

void               mpls_instr_release(struct mpls_instr *mi);
struct mpls_instr* mpls_instr_alloc(unsigned short opcode);
void               mpls_instrs_free(struct mpls_instr *list);
int                mpls_instrs_build(struct mpls_instr_elem *mie, 
				struct mpls_instr **instr, int length, 
				enum mpls_dir dir,void *parent);
void		   mpls_instrs_unbuild(struct mpls_instr *instr,
				struct mpls_instr_req *req);

/****************************************************************************
 * Layer 3 protocol driver
 *
 * most of this code is taken from DaveM&JHadi implementation
 ****************************************************************************/
#define MPLSPROTONAMSIZ 16
struct mpls_prot_driver {
	atomic_t	__refcnt;
	struct list_head list;

	unsigned short	family;
	unsigned short	ethertype;
	char		name[MPLSPROTONAMSIZ + 1];

	void		(*cache_flush)(struct net *net);
	void		(*set_ttl)(struct sk_buff *skb, int ttl);
	int		(*get_ttl)(struct sk_buff *skb);
	void		(*change_dsfield)(struct sk_buff *skb, int ds);
	int		(*get_dsfield)(struct sk_buff *skb);
	int		(*ttl_expired)(struct sk_buff **skb);
	int		(*mtu_exceeded)(struct sk_buff **skb, int mtu);
	int		(*local_deliver)(struct sk_buff *skb);

	int		(*nexthop_resolve)(struct neighbour **,
				struct sockaddr *, struct net_device *);

	struct module	*owner;
};

/****************************************************************************
 * Protocol driver Management 
 * net/mpls/mpls_proto.c
 ****************************************************************************/

void                     mpls_proto_init(void);
void                     mpls_proto_exit(void);
int                      mpls_proto_add(struct mpls_prot_driver *);
int                      mpls_proto_remove(struct mpls_prot_driver *);
struct mpls_prot_driver *mpls_proto_find_by_family(unsigned short);
struct mpls_prot_driver *mpls_proto_find_by_ethertype(unsigned short);
struct mpls_prot_driver *mpls_proto_find_by_name(char *);
void                     mpls_proto_cache_flush_all (struct net *);

#define mpls_proto_release(V)   atomic_dec((&V->__refcnt));
#define mpls_proto_hold(V)      atomic_inc((&V->__refcnt));

/****************************************************************************
 * MPLS INPUT INFO (ILM) OBJECT MANAGEMENT
 * net/mpls/mpls_ilm.c
 ****************************************************************************/

struct mpls_ilm {

	union {
		struct dst_entry     dst;
		struct mpls_ilm *next;
	} u;

	struct list_head             global;

	/* To appear as an entry in the device ILM list                     */ 
	struct list_head             dev_entry;
	/* Generic stats						    */
	struct gnet_stats_basic	     ilm_stats;
	unsigned int		     ilm_drops;
	/* List of NHLFE                                                    */ 
	struct list_head             nhlfe_entry;
	/* Instructions to execute for this ILM                             */ 
	struct mpls_instr           *ilm_instr;
	/* Incoming Label for this ILM                                      */
	struct mpls_label            ilm_label;
	/* Key used to lookup this object in a data structure               */
	unsigned int                 ilm_key;
	/* Jiffies                                                          */
	unsigned int                 ilm_age;
	/* L3 protocol driver for packets that use this ILM                 */
	struct mpls_prot_driver     *ilm_proto;
	/* Incoming Labelspace (see doc)                                    */
	unsigned short               ilm_labelspace;
	/* execute mpls_finish() before delivering locally		    */
	unsigned short               ilm_fix_hh;
};


/****************************************************************************
 * Input Radix Tree Management
 ****************************************************************************/

extern spinlock_t               mpls_ilm_lock;
extern struct radix_tree_root   mpls_ilm_tree;

int               mpls_ilm_init(void);
void              mpls_ilm_exit(void);
int               mpls_insert_ilm(unsigned int, struct mpls_ilm* ilm);
struct mpls_ilm*  mpls_delete_ilm(unsigned int key);
struct mpls_ilm*  mpls_get_ilm(unsigned int key);
struct mpls_ilm*  mpls_get_ilm_by_label(struct mpls_label *label,
				int labelspace, char bos);
extern struct mpls_ilm* mpls_ilm_dst_alloc(unsigned int key,
				struct mpls_label *ml, unsigned short family,
				struct mpls_instr_elem *instr, int instr_len,
				struct net_device *dev, int flags);



/****************************************************************************
 * MPLS OUTPUT INFO (NHLFE) OBJECT MANAGEMENT
 * net/mpls/mpls_ilm.c
 ****************************************************************************/

struct mpls_nhlfe {
	/* since most higher lay protocol operate on dst_entries, representing
	 * a NHLFE as a dst_enttry make sense.  Higher layer protocols
	 * may hold references to the dst_entry.  The result is that
	 * a NHLFE may exist after the user deletes it from the RADIX tree.
	 */
	union {
		struct dst_entry	dst;
		struct mpls_nhlfe	*next;
	} u;
#define nhlfe_mtu		u.dst._metrics

	/* user configured references as opposed to the references
	 * created by protocol drivers (ie IPv4 route cache)
	 */
	atomic_t		__refcnt;

	struct list_head	global;

	/* Generic stats						    */
	struct gnet_stats_basic	nhlfe_stats;
	unsigned int		nhlfe_drops;
	/* List of notif                                                    */
	struct notifier_block*  nhlfe_notifier_list;
	/* List of NHLFE that are linked to this NHLFE                      */
	struct list_head        list_out;
	/* List of ILM that are linked to this NHLFE                        */
	struct list_head        list_in;
	/* To be added into a device list_out if the NHLFE uses (SET) the dev */
	struct list_head        dev_entry;
	/* To be added into list_out if this nhlfe uses (FWD) another NHLFE */
	struct list_head        nhlfe_entry;
	/* Array of instructions for this NHLFE                             */ 
	struct mpls_instr      *nhlfe_instr;
	/* Key to used to store/lookup a given NHLFE in the tree            */
	unsigned int            nhlfe_key;
	/* Age in jiffies                                                   */
	unsigned int            nhlfe_age;
	/* MTU Limit (e.g. from device MTU + number of pushes               */
	unsigned short          nhlfe_mtu_limit;
	unsigned char           nhlfe_propagate_ttl;
};


struct mpls_fwd_block {
	struct notifier_block notifier_block;
	struct mpls_nhlfe *owner;
	struct mpls_nhlfe *fwd;
};

/****************************************************************************
 * Output Radix Tree Management
 ****************************************************************************/

extern struct radix_tree_root mpls_nhlfe_tree;
extern spinlock_t             mpls_nhlfe_lock;

int                 mpls_nhlfe_init(void);
void                mpls_nhlfe_exit(void);
int                 mpls_insert_nhlfe(unsigned int, struct mpls_nhlfe*);
struct mpls_nhlfe*  mpls_delete_nhlfe(unsigned int);
struct mpls_nhlfe*  mpls_get_nhlfe(unsigned int);


/****************************************************************************
 * Helper Functions
 ****************************************************************************/

void                mpls_skb_dump(struct sk_buff* sk);
char                mpls_find_payload(struct sk_buff* skb);
unsigned int        mpls_label2key(const int, const struct mpls_label*);


/****************************************************************************
 * INCOMING (INPUT) LABELLED PACKET MANAGEMENT
 * net/mpls/mpls_input.c
 ****************************************************************************/

int  mpls_skb_recv    (struct sk_buff *skb, struct net_device *dev,
                              struct packet_type* ptype, struct net_device *orig);
int  mpls_skb_recv_mc (struct sk_buff *skb, struct net_device *dev,
                              struct packet_type* ptype, struct net_device *orig);


/****************************************************************************
 * OUTGOING (OUTPUT) LABELLED PACKET MANAGEMENT
 * net/mpls/mpls_output.c
 ****************************************************************************/

struct mpls_dst {
	union {
		struct dst_entry	dst;
		struct mpls_dst		*next;
        } u;

	struct sockaddr			md_nh;
};

int  mpls_bogus_output(struct sk_buff *skb);
int  mpls_set_nexthop(struct shim_blk* blk,struct dst_entry *dst);
int  mpls_set_nexthop2(struct mpls_nhlfe *nhlfe, struct dst_entry *dst);
int  mpls_output(struct sk_buff *skb); 
int  mpls_switch(struct sk_buff *skb); 
int  mpls_output_shim (struct sk_buff *skb, struct mpls_nhlfe *nhlfe);
int  mpls_output2(struct sk_buff *skb,struct mpls_nhlfe *nhlfe);

extern void (*mpls_interrupt)(int, void *, struct pt_regs *);//add by here
void mpls_regular_interrupt(int irq, void *dev_id, struct pt_regs *regs); // add by here
void mpls_napi_interrupt(int irq, void *dev_id, struct pt_regs *regs); //add by here
int  mpls_re_tx(struct sk_buff *skb, struct net_device *dev);//add by here
int mpls_re_tx(struct sk_buff *skb, struct net_device *dev);//add by here
int mpls_tunnel_xmit (struct sk_buff *skb, struct net_device *dev); //add by here 

/****************************************************************************
 * MPLS Destination (dst) Next hop (neighbour) cache management
 * net/mpls/mpls_dst.c
 ****************************************************************************/

int              mpls_dst_init(void);
void             mpls_dst_exit(void);
struct mpls_dst *mpls_dst_alloc(struct net_device *dev, struct sockaddr *nh);
void             mpls_dst_release(struct mpls_dst *);


/****************************************************************************
 * INPUT/OUTPUT INSTRUCTION OPCODES 
 * net/mpls/{mpls_opcode,mpls_opcode_in,mpls_opcode_out}.c
 *
 ****************************************************************************/
 
/*
 * skb:       Socket buffer. May be modified [OUT] 
 * ilm:       ILM entry object that owns this opcode. 
 * nhlfe:       NHLF entry to apply. May be modified (e.g. MTU) [OUT] 
 * data:      opcode dependant data. Cast to NHLFEs, DS marks, etc.
 */
#define MPLS_OPCODE_PROTOTYPE(NAME) \
int (NAME) (struct sk_buff** skb,struct mpls_ilm *ilm, \
	struct mpls_nhlfe **nhlfe, void *data) 

/*
 * instr:     Instruction array. 
 * direction: MPLS_IN (ILM) or MPLS_OUT(NHLFE)
 * parent:    ILM/NHLFE parent object for opcode.
 * data:      opcode dependant data. [OUT]
 * last_able: Nonzero if this can be the last opcode. [OUT]
 * num_push:  Number of pushes for this opcode. [OUT] (Incr. by OP_PUSH
 */
#define MPLS_BUILD_OPCODE_PROTOTYPE(NAME) \
int (NAME) (struct mpls_instr_elem *instr, \
	enum mpls_dir direction, void *parent,\
        void **data, int *last_able, int *num_push)

/*
 * instr:     Instruction array. 
 * data:      opcode dependant data. [OUT]
 */
#define MPLS_UNBUILD_OPCODE_PROTOTYPE(NAME) \
int (NAME) (struct mpls_instr_elem *instr, void *data)

/*
 * data:      opcode dependant data.
 * parent:    ILM/NHLFE parent object for opcode.
 * direction: MPLS_IN (ILM) or MPLS_OUT(NHLFE)
 */
#define MPLS_CLEAN_OPCODE_PROTOTYPE(NAME) \
void (NAME) (void *data, void *parent, enum mpls_dir direction)

/*
 * seq:       seq_file output stream. 
 * data:      opcode dependant data.
 * direction: MPLS_IN (ILM) or MPLS_OUT(NHLFE)
 */
#define MPLS_PRINT_OPCODE_PROTOTYPE(NAME) \
void (NAME) (struct seq_file *seq, void *data, enum mpls_dir direction)

#define MPLS_IN_OPCODE_PROTOTYPE(NAME)  MPLS_OPCODE_PROTOTYPE(NAME) 
#define MPLS_OUT_OPCODE_PROTOTYPE(NAME) MPLS_OPCODE_PROTOTYPE(NAME) 

struct mpls_ops {
	MPLS_IN_OPCODE_PROTOTYPE(*in);
	MPLS_OUT_OPCODE_PROTOTYPE(*out);
	MPLS_BUILD_OPCODE_PROTOTYPE(*build);
	MPLS_UNBUILD_OPCODE_PROTOTYPE(*unbuild);
	MPLS_CLEAN_OPCODE_PROTOTYPE(*cleanup);
	MPLS_PRINT_OPCODE_PROTOTYPE(*print);
	int  extra;
	char *msg;
};

/* Array holding opcodes */
extern struct mpls_ops mpls_ops[];

struct sk_buff *mpls_finish(struct sk_buff *skb);
int    mpls_opcode_peek(struct sk_buff *skb);
int    mpls_push(struct sk_buff **skb, struct mpls_label *label);


/* Query/Update Incoming Labels */
int  mpls_add_in_label        (const struct mpls_in_label_req *in);
int  mpls_get_in_label        (struct mpls_in_label_req *in);
void __mpls_del_in_label      (struct mpls_ilm *ilm);
int  mpls_del_in_label        (struct mpls_in_label_req *in);
int  mpls_set_in_label_proto  (struct mpls_in_label_req *in);
int  mpls_add_reserved_label  (int label, struct mpls_ilm* ilm);
struct mpls_ilm* mpls_del_reserved_label (int label);

/* Query/Update Outgoing Labels */
extern int mpls_add_out_label     (struct mpls_out_label_req *out, int seq,
				   int pid, struct net_device *dev);
int mpls_get_out_label     (struct mpls_out_label_req *out);
int mpls_del_out_label     (struct mpls_out_label_req *out);
int mpls_set_out_label_mtu (struct mpls_out_label_req *out);

/* Query/Update Crossconnects */
int mpls_attach_in2out       (struct mpls_xconnect_req *req);
int mpls_detach_in2out       (struct mpls_xconnect_req *req);
int mpls_get_in2out          (struct mpls_xconnect_req *req);

/* Instruction Management */
int  mpls_set_in_label_instrs   (struct mpls_instr_req *mir);
int  mpls_set_out_label_instrs  (struct mpls_instr_req *mir);
int  mpls_set_in_instrs         (struct mpls_instr_elem *mie, 
	int length, struct mpls_ilm *ilm);
int  mpls_set_out_instrs        (struct mpls_instr_elem *mie, 
	int length, struct mpls_nhlfe *nhlfe);
int mpls_set_out_label_propagate_ttl(struct mpls_out_label_req *mol);

void mpls_destroy_out_instrs    (struct mpls_nhlfe *nhlfe);
void mpls_destroy_in_instrs     (struct mpls_ilm  *ilm);

/* Query/Update Labelspaces*/
int mpls_get_labelspace             (struct mpls_labelspace_req *req);
int mpls_get_labelspace_by_name     (const char *name);
int mpls_get_labelspace_by_index    (int ifindex);
int mpls_set_labelspace             (struct mpls_labelspace_req *req);
int mpls_set_labelspace_by_name     (const char *name, int labelspace);
int mpls_set_labelspace_by_index    (int ifindex, int labelspace);

struct net_device* mpls_tunnel_get_by_name (const char* name);
struct net_device* mpls_tunnel_get         (struct mpls_tunnel_req *mt);
void               mpls_tunnel_put         (struct net_device *dev);
struct net_device* mpls_tunnel_create      (struct mpls_tunnel_req *mt);
void               mpls_tunnel_destroy     (struct mpls_tunnel_req *mt);
int                mpls_tunnel_add         (struct mpls_tunnel_req *mt);
int                mpls_tunnel_del         (struct mpls_tunnel_req *mt);

/* Netlink event notification */
void mpls_ilm_event(int event, struct mpls_ilm *ilm);
void mpls_nhlfe_event(int event, struct mpls_nhlfe *nhlfe, int seq, int pid);
void mpls_labelspace_event(int event, struct net_device *dev);
void mpls_xc_event(int event, struct mpls_ilm *ilm,
	struct mpls_nhlfe *nhlfe);
//void mpls_tunnel_event(int event, struct net_device *dev);
void mpls_tunnel_event(int event);

/****************************************************************************
 * REFERENCE COUNT MANAGEMENT 
 ****************************************************************************/

/* Hold */
static inline struct mpls_ilm* mpls_ilm_hold(struct mpls_ilm* ilm)
{
	BUG_ON(!ilm);
	dst_hold (&ilm->u.dst);
	return ilm;
}


/* Release */
static inline void mpls_ilm_release(struct mpls_ilm* ilm)
{
	BUG_ON(!ilm);
	dst_release(&ilm->u.dst);
}


/* Hold */
static inline struct mpls_nhlfe* mpls_nhlfe_hold(struct mpls_nhlfe* nhlfe)
{
	BUG_ON(!nhlfe);
	atomic_inc(&nhlfe->__refcnt);
	return nhlfe;
}

/* Release */
static inline void mpls_nhlfe_release(struct mpls_nhlfe* nhlfe)
{
	BUG_ON(!nhlfe);
	atomic_dec(&nhlfe->__refcnt);
}

/****************************************************************************
 * sysctl Implementation
 * net/mpls/sysctl_net_mpls.c
 ****************************************************************************/

int   mpls_sysctl_init(void);
void  mpls_sysctl_exit(void);

/****************************************************************************
 * ProcFS Implementation
 * net/mpls/mpls_procfs.c
 ****************************************************************************/

//int   mpls_procfs_init(void);
//void  mpls_procfs_exit(void);

/****************************************************************************
 * Shim Implementation
 * net/mpls/mpls_shim.c
 ****************************************************************************/

void  mpls_shim_init(void);
void  mpls_shim_exit(void);

/****************************************************************************
 * NetLink Implementation  
 * net/mpls/mpls_netlink.c
 ****************************************************************************/

int  mpls_netlink_init (void);
void mpls_netlink_exit (void);

/****************************************************************************
 * Virtual Intefaces (Tunnel) Management 
 * (e.g. mpls0, mpls1, TXXethN, etc.)
 * net/mpls/mpls_tunnel.c
 ****************************************************************************/

struct mpls_tunnel_private {
	/* NHLFE Object to apply to this tunnel traffic */
	struct mpls_nhlfe             *mtp_nhlfe;
	/* Netdevice for this tunnel                  */
	struct net_device             *mtp_dev;
	/* Next tunnel in list                        */
	struct mpls_tunnel_private    *next;
	/* Netdevice (this tunnel) traffic stats      */
	struct net_device_stats        stat;
	/*Add by here*/
	int status;
	struct mpls_packet *ppool;
	struct mpls_packet *rx_queue;  /* List of incoming packets */
	int rx_int_enabled;
	int tx_packetlen;
	u8 *tx_packetdata;
	struct sk_buff *skb;
	spinlock_t lock;
	struct napi_struct napi;
	/*end by here*/
};
/*
 * A structure representing an in-flight packet.
 */
struct mpls_packet{
	struct mpls_packet *next;
	struct net_device *dev;
	int	datalen;
	u8 data[ETH_DATA_LEN];
};

/* Casts */
#define _mpls_as_if(PTR)    ((struct mpls_interface*)(PTR))
#define _mpls_as_label(PTR) ((struct mpls_label*)(PTR))
#define _mpls_as_ilm(PTR)   ((struct mpls_ilm*)(PTR))
#define _mpls_as_nhlfe(PTR) ((struct mpls_nhlfe*)(PTR))
#define _mpls_as_dfi(PTR)   ((struct mpls_dsmark_fwd_info*)(PTR))
#define _mpls_as_nfi(PTR)   ((struct mpls_nfmark_fwd_info*)(PTR))
#define _mpls_as_efi(PTR)   ((struct mpls_exp_fwd_info*)(PTR))
#define _mpls_as_netdev(PTR)((struct net_device*)(PTR))
#define _mpls_as_dst(PTR)   ((struct mpls_dst*)(PTR))

#endif
