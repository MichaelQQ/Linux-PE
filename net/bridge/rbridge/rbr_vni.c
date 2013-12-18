/*
 *	Generic parts
 *	Linux ethernet Rbridge VNI
 *
 *	Authors:
 *	Ahmed Amamou	<ahmed@gandi.net>
 *	Kamel Haddadou	<kamel@gandi.net>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include "rbr_private.h"

struct vni *find_vni(struct net_bridge *br, uint32_t id) {
	struct vni *vni;

	if (!br)
		return NULL;
	list_for_each_entry(vni, &br->vni_list, list) {
		if (vni->vni_id == id)
			return vni;
	}
	return NULL;
}

static struct vni *create_vni(struct net_bridge *br, uint32_t id) {
	struct vni *vni;
	vni = find_vni(br, id);

	if (vni)
		return vni;
	vni = kzalloc(sizeof(*vni), GFP_KERNEL);
	if (vni == NULL)
		return ERR_PTR(-ENOMEM);
	list_add_rcu(&vni->list, &br->vni_list);
	INIT_LIST_HEAD(&vni->port_list);
	vni->br = br;
	vni->vni_id = id;
	return vni;
}

static bool port_has_vni(struct net_bridge_port *p) {
	if (p->vni)
		return (p->vni->vni_id ? true : false);
	return false;
}

uint32_t get_port_vni_id(struct net_bridge_port *p) {
	return (port_has_vni(p) ? p->vni->vni_id : 0);
}

void vni_del_port(struct net_bridge_port *p) {
	if (!p)
		return;
	if (!port_has_vni(p))
		return;
	list_del_rcu(&p->list2);
	p->vni = NULL;
}

bool vni_add_port(struct net_bridge_port *p, uint32_t id) {
	struct vni *vni;

	if (!p)
		return false;
	if ((port_has_vni(p)) && (p->vni->vni_id == id))
		return true;
	vni_del_port(p); /* remove old vni if it exist */
	vni = find_vni(p->br, id);
	if ((!vni) && !(vni = create_vni(p->br, id)))
		return false;
	p->vni = vni;
	list_add_rcu(&p->list2, &vni->port_list);
	return true;
}

static void destroy_vni_rcu(struct rcu_head *head)
{
	struct vni *vni = container_of(head, struct vni, rcu);

	kfree(vni);
}

void del_vni(struct vni* vni) {
	struct net_bridge_port *p, *n;

	list_for_each_entry_safe(p, n, &vni->port_list, list2) {
		vni_del_port(p);
	}
	list_del_rcu(&vni->list);
	call_rcu(&vni->rcu, destroy_vni_rcu);
}
