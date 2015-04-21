/*****************************************************************************
 * MPLS
 *      An implementation of the MPLS (MultiProtocol Label
 *      Switching Architecture) for Linux.
 *
 * Authors:
 *	  James Leu	<jleu@mindspring.com>
 *	  Ramon Casellas   <casellas@infres.enst.fr>
 *
 *   (c) 1999-2004   James Leu	<jleu@mindspring.com>
 *   (c) 2003-2004   Ramon Casellas   <casellas@infres.enst.fr>
 *
 *	      It implements:
 *	      -various common functions called by the rest of the MPLS
 *	       stack
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
 * RCAS BUGS: struct mpls_label should use u32, u16...
 ****************************************************************************/

#include <generated/autoconf.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/kobject.h>
#include <net/neighbour.h>
#include <net/route.h>
#include <net/mpls.h>

/**************
  ATM
   0		   1		   2		   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |Label Space(10)    |    VPI (8)    |	  VCI(16)		  |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |typ|     index(8)  |	   VPI (8)    |	  VCI(16)		  |
  +---------------------------------------------------------------+
  |	       mark (key)				          |
  +---------------------------------------------------------------+

  Generic
   0		   1		   2		   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |   Label Space(12)     |       Generic Label Value(20)	  |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |typ|    index(10)      |		   gen(20)		  | 
  +---------------------------------------------------------------+
  |	       mark (key)				          |
  +---------------------------------------------------------------+

  Frame Relay
   0		   1		   2		   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |Label Space(12)  	  |	      DLCI(20)			  |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |typ|    index(10)      |		   fr(20)		  | 
  +---------------------------------------------------------------+
  |	       mark (key)				          |
  +---------------------------------------------------------------+

 *************/

struct mpls_atm_key {
	unsigned int type:2;
	unsigned int index:8;
	unsigned int vpi:8;
	unsigned int vci:14;
};

struct mpls_gen_key {
	unsigned int type:2;
	unsigned int index:10;
	unsigned int gen:20;
};

struct mpls_fr_key {
	unsigned int type:2;
	unsigned int index:10;
	unsigned int fr:20;
};

struct mpls_key {
	union {
		struct mpls_atm_key atm;
		struct mpls_gen_key gen;
		struct mpls_fr_key  fr;
		unsigned int mark:32;
	} u;
};



/** 
 *	mpls_label2key - Obtain a lookup key given a index or labelspace
 *	and a label value.
 *	@index: labelspace
 *	@label: struct containing the label type/value.
 *
 *	Returns a given key that can be used to store/read objects in a 
 *	data structure (e.g. a Radix Tree).
 *
 *	Bugs: RCAS: this function must be *faast* optimize!
 **/

unsigned int  
mpls_label2key (const int index, const struct mpls_label *label) 
{
	struct mpls_key temp;

	switch(label->ml_type) {
		case MPLS_LABEL_GEN:
			temp.u.gen.index = index;
			temp.u.gen.gen   = label->u.ml_gen;
			temp.u.gen.type  = label->ml_type;
			break;
		case MPLS_LABEL_ATM:
			temp.u.atm.index = index;
			temp.u.atm.vpi   = label->u.ml_atm.mla_vpi;
			temp.u.atm.vci   = label->u.ml_atm.mla_vci;
			temp.u.atm.type  = label->ml_type;
			break;
		case MPLS_LABEL_FR:
			temp.u.fr.index  = index;
			temp.u.fr.fr     = label->u.ml_fr;
			temp.u.fr.type   = label->ml_type;
			break;
		case MPLS_LABEL_KEY:
			temp.u.mark      = label->u.ml_key;
			break;
	}
	return temp.u.mark;
}

/**
 *	mpls_find_payload - find the beinging of the data under the
 *	mpls shim
 *	@skb - the packet to work on
 *
 *	assumes valid data in MPLSCB(skb)->popped_bos and that
 *	that skb_network_header(skb) is pointing to a label in the MPLS shim
 *	returns a unsigned char* which point to the first byte after the MPLS
 *	shim.
 *
 **/

char
mpls_find_payload (struct sk_buff* skb)
{
	unsigned char *ptr = skb->data;
	unsigned char count = 0;
        u32 shim;

	if (MPLSCB(skb)->popped_bos)
		return count;

try_again:

	if (ptr > skb_tail_pointer(skb))
		return -1;

#define CAN_WE_ASSUME_32BIT_ALIGNED 0
#if CAN_WE_ASSUME_32BIT_ALIGNED
        shim = ntohl(*((u32*)ptr));
#else
        memcpy(&shim,ptr,MPLS_SHIM_SIZE);
        shim = ntohl(shim);
#endif

	ptr = &ptr[MPLS_SHIM_SIZE];
	count += MPLS_SHIM_SIZE;

        if ((shim >> 8 ) & 0x1)
	    return count;

	goto try_again;

        return 0;
}

/**
 *	mpls_skb_dump - dump socket buffer to kernel log.
 *	@sk received socket buffer
 *	
 *	Dumps the content of the socket buffer to the kernel log buffer. Can be 
 *	called from anywhere, but typically it is called upon reception of a
 *	labelled packet.
 *
 **/

void 
mpls_skb_dump (struct sk_buff* sk) 
{
	unsigned long i;
	printk("MPLS mpls_skb_dump: from %s with len %d (%d)" 
	       "headroom=%d tailroom=%d\n",
			sk->dev?sk->dev->name:" net stack ",
			sk->len,
			sk->truesize,
			skb_headroom(sk),
			skb_tailroom(sk));

	for (i=(unsigned long)sk->head; i<=(unsigned long)skb_tail_pointer(sk); i++) {
		if (i == (unsigned long)sk->data)
			printk("{"); 
		if (i == (unsigned long)skb_transport_header(sk))
			printk("#");
		if (i == (unsigned long)skb_network_header(sk))
			printk("|"); 
		if (i == (unsigned long)skb_mac_header(sk))
			printk("*"); 
		printk("%02x",*((unsigned char*)i));
		if (i == (unsigned long)skb_tail_pointer(sk))
			printk("}"); 
	}
	printk("\n");
}

EXPORT_SYMBOL(mpls_label2key);
EXPORT_SYMBOL(mpls_find_payload);
EXPORT_SYMBOL(mpls_skb_dump);
