/*
 *	Generic parts
 *	Linux ethernet Rbridge
 *
 *	Authors:
 *	Ahmed AMAMOU		<ahmed@gandi.net>
 *	Kamel Haddadou	<kamel@gandi.net>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include "../br_private.h"
static struct rbr *add_rbr(struct net_bridge *br)
{
  struct rbr *rbr;
  char rbr_name[IFNAMSIZ];
  if (!br->rbr){
    rbr = kzalloc(sizeof(struct rbr), GFP_KERNEL);
    if(!rbr)
	return NULL;
    strcpy(rbr_name, "");
    strncat(rbr_name, br->dev->name, IFNAMSIZ-4);
    strcat(rbr_name, "_rbr");
    spin_lock_bh(&br->lock);
    strncpy(rbr->name, rbr_name, IFNAMSIZ);
    strncpy(rbr->rbr_bridgename, br->dev->name, IFNAMSIZ);
    rbr->br = (struct net_bridge *)br;
    rbr->nick = RBRIDGE_NICKNAME_NONE;
    rbr->treeroot = RBRIDGE_NICKNAME_NONE;
    spin_unlock_bh(&br->lock);
    return rbr;
  }
  else{
    return br->rbr;
  }
}
static void br_trill_start(struct net_bridge *br)
{
	br->rbr = add_rbr(br);
	if(br->rbr){
	  spin_lock_bh(&br->lock);
	  br->trill_enabled = BR_TRILL;
	  spin_unlock_bh(&br->lock);
	}
	else{
	  printk(KERN_WARNING"RBridge allocation for bridge '%s' failed\n",
										br->dev->name);
	}
}

static void br_trill_stop(struct net_bridge *br)
{
	struct rbr * old;
	spin_lock_bh(&br->lock);
	br->trill_enabled = BR_NO_TRILL;
	spin_unlock_bh(&br->lock);
	old = br->rbr;
	br->rbr = NULL;
	if(old)
	{
	  spin_lock_bh(&br->lock);
	  kfree(old);
	  spin_unlock_bh(&br->lock);
	}
}

int set_treeroot(struct rbr *rbr, uint16_t treeroot)
{

	if(!VALID_NICK(treeroot)){
	  pr_warn_ratelimited("rbr_set_treeroot: given tree root not valid\n");
	  goto set_tree_root_fail;
	}
	if (rbr->treeroot != treeroot){
	  spin_lock_bh(&rbr->br->lock);
	  rbr->treeroot = treeroot;
	  spin_unlock_bh(&rbr->br->lock);
	}
	return 0;
set_tree_root_fail:
	return ENOENT;
}

void br_trill_set_enabled(struct net_bridge *br, unsigned long val)
{
	if (val) {
	  if (br->trill_enabled == BR_NO_TRILL)
	    br_trill_start(br);
	} else {
	  if (br->trill_enabled != BR_NO_TRILL)
	    br_trill_stop(br);
	}
}
