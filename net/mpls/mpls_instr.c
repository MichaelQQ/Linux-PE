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
 *	      -instruction maintainace
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
 * Changes
 *	JLEU: convert rt_cache_flush() to mpls_proto_cache_flush_all()
 *
 ****************************************************************************/

#include <generated/autoconf.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <net/neighbour.h>
#include <net/route.h>
#include <net/mpls.h>


/**
 *	mpls_instr_alloc - Allocate a mpls_instruction object
 *	@opcode: opcode num.
 **/

struct mpls_instr*
mpls_instr_alloc (unsigned short opcode)
{
	struct mpls_instr  *mi;

	mi = kmalloc(sizeof(struct mpls_instr), GFP_ATOMIC);
	if (likely(mi)) {
		memset (mi, 0, sizeof(struct mpls_instr));
		mi->mi_opcode = opcode;
	}
	return mi;
}

/**
 *	mpls_instr_release - destructor for mpls instruction.
 *	@mi: this instruction
 *
 **/

void 
mpls_instr_release (struct mpls_instr *mi)
{
	unsigned short op	= mi->mi_opcode;
	void *data		= mi->mi_data;
	void *parent		= mi->mi_parent;
	enum mpls_dir dir	= mi->mi_dir;

	MPLS_ENTER;

	if ((mpls_ops[op].cleanup) && data) 
		mpls_ops[op].cleanup (data, parent, dir);

	/* Poisson */
	memset(mi,0xae,sizeof(struct mpls_instr));
	kfree (mi);
	MPLS_EXIT;
}


/**
 *	mpls_instrs_free - free an instruction set. 
 *	@instr:       Instruction list 
 *
 **/
 
void
mpls_instrs_free (struct mpls_instr *list)
{
	struct mpls_instr* mi  = list;
	struct mpls_instr *tmp = NULL;

	MPLS_ENTER;
	while (mi) {
		tmp = mi->mi_next;
		mpls_instr_release (mi);
		mi = tmp;
	}
	MPLS_EXIT;
}

/**
 *	mpls_instrs_build - build up an instruction set. 
 *	@mie:	 Instruction Element array 
 *	@instr:       Instruction list [OUT]
 *	@length:      Number of valid entries in the array
 *	@dir:	 MPLS_IN for ILMs (ILM) or MPLS_OUT for NHLFEs (NHLFE).
 *	@parent:      ILM/NHLFE "parent object".
 *
 *	This function constructs a "instr/operation set", the set of 
 *	opcodes to execute with the corresponding data for a given ILM/NHLFE
 *	object.
 *
 *	Returns the number of valid entries.
 **/
 
int 
mpls_instrs_build (struct mpls_instr_elem *mie, struct mpls_instr **instr, 
	int length, enum mpls_dir  dir,   void *parent) 
{
	
	struct mpls_instr **pmi = instr;  /* Instruction List */
	unsigned short opcode = 0;	  /* Opcode interator */
	unsigned short i = 0;		  /* Element iterator */
	int num_push  = 0;		  /* Total # of pushes */
	int last_able = 0;		  /* This must be true at end */
	MPLS_BUILD_OPCODE_PROTOTYPE(*f);  /* Build Operation */
	struct mpls_instr  *mi;		  /* MPLS Instruction Iterator */
	void *data;
	int ret       = -ENXIO;

	MPLS_ASSERT(*instr == NULL);

	/* Iterate the instr set */
	for (i = 0; i < length; i++) {
		opcode  = mie[i].mir_opcode;
		f       = mpls_ops[opcode].build;
		if (unlikely(!f))
			goto rollback; 

		mi      = mpls_instr_alloc(opcode); 
		if (unlikely(!mi))
			goto rollback;	

		data    = NULL;
		*pmi = mi;

		/* Build the opcode.
		 * Input : parent ILM/NHLFE, elem & direcion.
		 * Output: cumul pushes for this ILM/NHLFE,last?, data */
		ret = f(&mie[i],dir,parent,&data,&last_able,&num_push);
		if (ret)
			goto rollback; 

		mi->mi_data   = data;
		mi->mi_parent = parent;
		mi->mi_dir    = dir;
		pmi = &mi->mi_next;
	}

	/* Make sure the last one was valid */
	if (!last_able) {
		printk (KERN_ERR "MPLS: invalid last op %s, len = %d(%d)\n",
			mpls_ops[opcode].msg, i, length);
		goto rollback;
	}

	MPLS_ASSERT(*instr);

	/*
	 * it is possible that the MTU of a NHLFE may have changed.
	 * to be paranoid, flush the layer 3 caches
	 */
	mpls_proto_cache_flush_all(&init_net);

	return i;

rollback:
	mi  = *instr;
	mpls_instrs_free(mi);
	*instr = NULL;
	return 0;
}

void
mpls_instrs_unbuild(struct mpls_instr *instr, struct mpls_instr_req *req)
{
        MPLS_UNBUILD_OPCODE_PROTOTYPE(*func);
        struct mpls_instr *mi;
        int c = 0;

        MPLS_ENTER;

        for (mi = instr;mi;mi = mi->mi_next) {
                req->mir_instr[c].mir_opcode = mi->mi_opcode;
                func = mpls_ops[mi->mi_opcode].unbuild;

                if (func)
                        func(&req->mir_instr[c],mi->mi_data);
                c++;
        }

        req->mir_instr_length = c;

        MPLS_EXIT;
}

EXPORT_SYMBOL(mpls_instrs_build);
EXPORT_SYMBOL(mpls_instrs_unbuild);
EXPORT_SYMBOL(mpls_instrs_free);
