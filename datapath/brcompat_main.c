/*
 * Copyright (c) 2007-2012 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

/*
 * Includes Inango Systems Ltd’s changes/modifications dated: 2021.
 * Changed/modified portions - Copyright (c) 2021 , Inango Systems Ltd.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/delay.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/completion.h>
#include <linux/etherdevice.h>
#include <linux/if_bridge.h>
#include <linux/kconfig.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <net/br_compat.h>
#include <net/genetlink.h>
#include <net/rtnetlink.h>

#include "datapath.h"
#include "openvswitch/brcompat-netlink.h"
#include "vport-internal_dev.h"
#include "vport-netdev.h"

#ifdef HAVE_GENL_MULTICAST_GROUP_WITH_ID
#define GROUP_ID(grp)	((grp)->id)
#else
#define GROUP_ID(grp)	0
#endif

#define BRIDGE_LIST_MAX 16

/* Dafaults */
#define BRC_STP_DEFAULT_BRIDGE_PRIORITY 32768
/* Default time values. */
#define BRC_STP_DEFAULT_MAX_AGE    20
#define BRC_STP_DEFAULT_HELLO_TIME 2
#define BRC_STP_DEFAULT_FWD_DELAY  15
/* Default mac-aging-time is y 300 seconds (5 minutes)*/
#define BRC_DEFAULT_MAC_AGING_TIME 300
#define BRC_STP_PATH_COST   100

/* Bridge ioctls */
#define SIOCBRMGADD           0x89ab
#define SIOCBRMGDEL           0x89ac
#define SIOCBRSETROUTERPORT   0x89ad
#define SIOCBRENABLESNOOPING  0x89ae

/* kernel/net/bridge/br_private.h */
typedef enum {
	IPV4 = 0,
	IPV6,
} ptype_t;

struct ipaddr {
	ptype_t type;
	union {
		struct in_addr  ip4;
		struct in6_addr ip6;
	} addr;
};

typedef struct ipaddr ipaddr_t;

/* mcast_service/daemon_mcast_src/LQ_MCASTD_includes.h */
struct br_grp_mem {
	unsigned int if_idx;       /* interface index */
	ipaddr_t     gaddr;
	unsigned int filter_mode;  /* Filter mode */
	unsigned int compat_mode;  /* Compatibility mode */
	unsigned int nsrc;         /* Number of sources */
	ipaddr_t     slist[0];     /* source list */
};
typedef struct br_grp_mem br_grp_mem_t;

/* Set router port ioctl request */
struct brc_router_port {
	ptype_t type;
	u32 if_index;	/* interface index */
	u32 expires;	/* expiry time */
};

static char *br_list[BRIDGE_LIST_MAX];
static unsigned int size_list = BRIDGE_LIST_MAX;
module_param_array_named(bridges, br_list, charp, &size_list, 0);
static br_ioctl_hook_t bridge_ioctl_hook;

static struct genl_family brc_genl_family;
static struct genl_multicast_group brc_mc_group = {
	.name = "brcompat"
};

const struct rtnl_link_ops *br_ovs_link_ops;
struct rtnl_link_ops *br_link_ops;
struct rtnl_link_ops br_compat_link_ops;

#ifdef CONFIG_LTQ_MCAST_SNOOPING
static struct net *brc_net = NULL;
#endif

/* Time to wait for ovs-vswitchd to respond to a datapath action, in
 * jiffies. */
#define BRC_TIMEOUT (HZ * 5)

/* Mutex to serialize ovs-brcompatd callbacks.  (Some callbacks naturally hold
 * br_ioctl_mutex, others hold rtnl_lock, but we can't take the former
 * ourselves and we don't want to hold the latter over a potentially long
 * period of time.) */
static DEFINE_MUTEX(brc_serial);

/* Userspace communication. */
static DEFINE_SPINLOCK(brc_lock);    /* Ensure atomic access to these vars. */
static DECLARE_COMPLETION(brc_done); /* Userspace signaled operation done? */
static struct sk_buff *brc_reply;    /* Reply from userspace. */
static u32 brc_seq;		     /* Sequence number for current op. */
static bool brc_netlink_flg = false; /* Flag that indicate that exist brcompat netlink processing */

static DEFINE_MUTEX(brc_addbr_lock); /* Ensure atomic bridge adding. */
static struct net_device *netlink_dev; /* Pointer to net_device allocated in kernel,
					  in case of netlink newlink. Must be
					  processed under brc_addbr_lock. */
static DEFINE_MUTEX(brc_name_lock);  /* Ensure atomic access to bridge_name. */
static char bridge_name[IFNAMSIZ] = {0};

static bool check_bridge_list(const char *name);
static struct sk_buff *brc_send_command(struct net *,
					struct sk_buff *,
					struct nlattr **attrs);
static int brc_send_simple_command(struct net *, struct sk_buff *);
static int brc_get_ulong_val_cmd(struct net_device *dev, int oper, unsigned long *uvalue);
static int brc_get_ulong_val_cmd_with_net(struct net *net, const char *bridge, int oper, unsigned long *uvalue);

static struct sk_buff *brc_make_request(int op, const char *bridge,
					const char *port)
{
	struct sk_buff *skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!skb)
		goto error;

	genlmsg_put(skb, 0, 0, &brc_genl_family, 0, op);

	if (bridge && nla_put_string(skb, BRC_GENL_A_DP_NAME, bridge))
		goto nla_put_failure;
	if (port && nla_put_string(skb, BRC_GENL_A_PORT_NAME, port))
		goto nla_put_failure;

	return skb;

nla_put_failure:
	kfree_skb(skb);
error:
	return NULL;
}

static int brc_send_simple_command(struct net *net, struct sk_buff *request)
{
	struct nlattr *attrs[BRC_GENL_A_MAX + 1];
	struct sk_buff *reply;
	int error;

	reply = brc_send_command(net, request, attrs);
	if (IS_ERR(reply))
		return PTR_ERR(reply);

	error = nla_get_u32(attrs[BRC_GENL_A_ERR_CODE]);
	kfree_skb(reply);
	return -error;
}

static int brc_add_del_bridge(struct net *net, struct net_device *dev,
			      char *name, char *mac, int add)
{
	struct sk_buff *request;
	int result;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	request = brc_make_request(add, name, NULL);
	if (!request)
		return -ENOMEM;
#ifdef CONFIG_LTQ_MCAST_SNOOPING
	if (!brc_net)
		brc_net = net;
#endif

	if (mac && nla_put(request, BRC_GENL_A_MAC_ADDR, ETH_ALEN, mac)) {
		printk(KERN_ERR "Can't provide MAC address configuration into OVS (dev=\"%s\", mac=%pM )\n", name, mac);
		kfree_skb(request);
		return -ENOMEM;
	}


	/* if (add == BRC_GENL_C_DP_ADD) */
	mutex_lock(&brc_addbr_lock);
	netlink_dev = dev;

	mutex_lock(&brc_name_lock);
	strcpy(bridge_name, name);
	mutex_unlock(&brc_name_lock);

	result = brc_send_simple_command(net, request);

	mutex_lock(&brc_name_lock);
	*bridge_name = '\0';
	mutex_unlock(&brc_name_lock);

	netlink_dev = NULL;
	mutex_unlock(&brc_addbr_lock);

	return result;
}

static struct net_device *brc_get_netdev()
{
	return netlink_dev;
}

static int brc_add_del_bridge_netlink(struct net *net, struct net_device *dev, int add)
{
	int err;
	rtnl_unlock();
	if ((add == BRC_GENL_C_DP_ADD) && (dev->addr_assign_type == NET_ADDR_SET)) {
		err = brc_add_del_bridge(net, dev, dev->name, dev->dev_addr, add);
	} else {
		err = brc_add_del_bridge(net, dev, dev->name, NULL, add);
	}
	rtnl_lock();
	return err;
}

static int brc_add_bridge_netlink(struct net *net, struct net_device *dev)
{
	return brc_add_del_bridge_netlink(net, dev, BRC_GENL_C_DP_ADD);
}

static void brc_del_bridge_netlink(struct net *net, struct net_device *dev)
{
	brc_add_del_bridge_netlink(net, dev, BRC_GENL_C_DP_DEL);
}

static int brc_add_del_bridge_ioctl(struct net *net, char __user *uname, int add)
{
	char name[IFNAMSIZ];
	if (copy_from_user(name, uname, IFNAMSIZ))
		return -EFAULT;
	name[IFNAMSIZ - 1] = 0;
	return brc_add_del_bridge(net, NULL, name, NULL, add);
}

static int brc_get_indices(struct net *net,
			   int op, const char *br_name,
			   int __user *uindices, int n)
{
	struct nlattr *attrs[BRC_GENL_A_MAX + 1];
	struct sk_buff *request, *reply;
	int *indices;
	int ret;
	int len;

	if (n < 0)
		return -EINVAL;
	if (n >= 2048)
		return -ENOMEM;

	request = brc_make_request(op, br_name, NULL);
	if (!request)
		return -ENOMEM;

	reply = brc_send_command(net, request, attrs);
	ret = PTR_ERR(reply);
	if (IS_ERR(reply))
		goto exit;

	ret = -nla_get_u32(attrs[BRC_GENL_A_ERR_CODE]);
	if (ret < 0)
		goto exit_free_skb;

	ret = -EINVAL;
	if (!attrs[BRC_GENL_A_IFINDEXES])
		goto exit_free_skb;

	len = nla_len(attrs[BRC_GENL_A_IFINDEXES]);
	indices = nla_data(attrs[BRC_GENL_A_IFINDEXES]);
	if (len % sizeof(int))
		goto exit_free_skb;

	n = min_t(int, n, len / sizeof(int));
	ret = copy_to_user(uindices, indices, n * sizeof(int)) ? -EFAULT : n;

exit_free_skb:
	kfree_skb(reply);
exit:
	return ret;
}

static int brc_get_string(struct net_device *dev, int oper, char *ustring)
{
	struct nlattr *attrs[BRC_GENL_A_MAX + 1];
	struct sk_buff *request, *reply;
	char *string;
	int ret = 0;
	int len;

	request = brc_make_request(oper, dev->name, NULL);
	if (!request)
		return -ENOMEM;

	reply = brc_send_command(dev_net(dev), request, attrs);
	ret = PTR_ERR(reply);
	if (IS_ERR(reply))
		goto exit;

	ret = -nla_get_u32(attrs[BRC_GENL_A_ERR_CODE]);
	if (ret < 0)
		goto exit_free_skb;

	if (!attrs[BRC_GENL_A_GET_STRING]) {
		ret = -EINVAL;
		goto exit_free_skb;
	}

	len = nla_len(attrs[BRC_GENL_A_GET_STRING]);
	string = nla_data(attrs[BRC_GENL_A_GET_STRING]);

	if(string == NULL) {
		ret = -EINVAL;
		goto exit_free_skb;
	} else {
		memcpy(ustring, string, len);
	}
exit_free_skb:
	kfree_skb(reply);
exit:
	return ret;
}

/* Called with br_ioctl_mutex. */
static int brc_get_bridges(struct net *net, int __user *uindices, int n)
{
	return brc_get_indices(net, BRC_GENL_C_GET_BRIDGES, NULL, uindices, n);
}

static inline int bridge_ioctl_legacy_hook(struct net *net, struct net_bridge *br,
			     unsigned int cmd, struct ifreq *ifr, 
			     void __user *uarg)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,15,0)
	return bridge_ioctl_hook(net, cmd, uarg);
#else
	return bridge_ioctl_hook(net, br, cmd, ifr, uarg);
#endif
}

/* Legacy deviceless bridge ioctl's.  Called with br_ioctl_mutex. */
static int old_deviceless(struct net *net, void __user *uarg)
{
	int brc_ret, lbr_ret;
	unsigned long args[3];

	if (copy_from_user(args, uarg, sizeof(args)))
		return -EFAULT;

	switch (args[0]) {
	case BRCTL_GET_BRIDGES:
	{
		lbr_ret = bridge_ioctl_legacy_hook(net, NULL, SIOCGIFBR, NULL, uarg);
		if (lbr_ret < 0)
			return lbr_ret;

		brc_ret = brc_get_bridges(net, ((int __user *)args[1]) + lbr_ret , args[2] - lbr_ret);
		if (brc_ret < 0)
			return brc_ret;

		return lbr_ret + brc_ret;
	}
	case BRCTL_ADD_BRIDGE:
	{
		if (check_bridge_list((char __user *)args[1]))
			return brc_add_del_bridge_ioctl(net, (void __user *)args[1], BRC_GENL_C_DP_ADD);
		else
			return bridge_ioctl_legacy_hook(net, NULL, SIOCSIFBR, NULL, uarg);
	}
	case BRCTL_DEL_BRIDGE:
	{
		unsigned long br_exist_exit_code = 1;
		brc_get_ulong_val_cmd_with_net(net, (char __user *)args[1], BRC_GENL_C_GET_BRIDGE_EXISTS, &br_exist_exit_code);

		if (check_bridge_list((char __user *)args[1]) || br_exist_exit_code == 0)
			return brc_add_del_bridge_ioctl(net, (void __user *)args[1], BRC_GENL_C_DP_DEL);
		else
			return bridge_ioctl_legacy_hook(net, NULL, SIOCSIFBR, NULL, uarg);
	}
	}

	return -EOPNOTSUPP;
}



/* Called with the br_ioctl_mutex. */
static int
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,23)
brc_ioctl_deviceless_stub(unsigned int cmd, void __user *uarg)
{
	struct net *net = NULL;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5,15,0)
brc_ioctl_deviceless_stub(struct net *net, unsigned int cmd, 
			     void __user *uarg)
{
	struct net_bridge *br = NULL;
	struct ifreq *ifr = NULL;
#else
brc_ioctl_deviceless_stub(struct net *net, struct net_bridge *br,
			     unsigned int cmd, struct ifreq *ifr, 
			     void __user *uarg)
{
#endif
	switch (cmd) {
	case SIOCGIFBR:
	case SIOCSIFBR:
		return old_deviceless(net, uarg);

	case SIOCBRADDBR:
	{
		if (check_bridge_list((char __user *)uarg))
			return brc_add_del_bridge_ioctl(net, uarg, BRC_GENL_C_DP_ADD);
		else
			return bridge_ioctl_legacy_hook(net, br, cmd, ifr, uarg);
	}
	case SIOCBRDELBR:
	{
		if (check_bridge_list((char __user *)uarg))
			return brc_add_del_bridge_ioctl(net, uarg, BRC_GENL_C_DP_DEL);
		else
			return bridge_ioctl_legacy_hook(net, br, cmd, ifr, uarg);
	}
	}

	return -EOPNOTSUPP;
}

static int brc_add_del_port_dev(struct net_device *dev, struct net_device *port, int add)
{
	struct sk_buff *request;
	int err;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	/* Save name of dev and port because there's a race between the
	 * rtnl_unlock() and the brc_send_simple_command(). */
	request = brc_make_request(add ? BRC_GENL_C_PORT_ADD : BRC_GENL_C_PORT_DEL,
				   dev->name, port->name);
	if (!request)
		return -ENOMEM;

	rtnl_unlock();
	err = brc_send_simple_command(dev_net(dev), request);
	rtnl_lock();

	return err;
}

static int brc_add_del_port(struct net_device *dev, int port_ifindex, int add)
{
	struct net_device *port;

	port = __dev_get_by_index(dev_net(dev), port_ifindex);
	if (!port)
		return -EINVAL;

	return brc_add_del_port_dev(dev, port, add);
}

/* seamless-ovs { */
static int brc_add_del_mg_rec(struct net_device *dev, br_grp_mem_t *rec, int add)
{
	struct sk_buff    *request;
	struct net_device *port;
	int                err;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	port = __dev_get_by_index(dev_net(dev), rec->if_idx);
	if (!port)
		return -EINVAL;

	/* debug prints */
	#if 0
	printk("brc_add_del_mg_rec(add=%d): if_idx=%u, dev=%s, port=%s, gaddr.type=%s\n", add, rec->if_idx, dev->name, port->name, rec->gaddr.type == IPV4 ? "ipv4" : "ipv6");
	#endif

	/* Save name of dev and port because there's a race between the
	 * rtnl_unlock() and the brc_send_simple_command(). */
	request = brc_make_request(add ? BRC_GENL_C_MG_ADD : BRC_GENL_C_MG_DEL, dev->name, port->name);
	if (!request)
		return -ENOMEM;

	if (nla_put(request, BRC_GENL_A_MG_GADDR, sizeof(rec->gaddr), &rec->gaddr))
		goto brc_add_del_mg_rec_put_failure;

	if (add) {
		if (nla_put_u32(request, BRC_GENL_A_MG_FILTER, rec->filter_mode))
			goto brc_add_del_mg_rec_put_failure;

		if (nla_put_u32(request, BRC_GENL_A_MG_COMPAT, rec->compat_mode))
			goto brc_add_del_mg_rec_put_failure;

		if (nla_put_u32(request, BRC_GENL_A_MG_NSRC, rec->nsrc))  /* Number of sources -> unsigned int */
			goto brc_add_del_mg_rec_put_failure;

		if (rec->nsrc) {
			if (nla_put(request, BRC_GENL_A_MG_SADDR, rec->nsrc * sizeof(rec->slist[0]), rec->slist))
				goto brc_add_del_mg_rec_put_failure;
		}

		/* debug prints */
		#if 0
		if (rec->gaddr.type == IPV4)
			printk("brc_add_del_mg_rec(add=1): if_idx=%u, dev=%s, port=%s, gaddr=0x%08x, filter=%u, compat=%u, nsrc=%u\n", rec->if_idx, dev->name, port->name, rec->gaddr.addr.ip4.s_addr, rec->filter_mode, rec->compat_mode, rec->nsrc);
		else {
			__be32 *ip6_32 = rec->gaddr.addr.ip6.s6_addr32;
			printk("brc_add_del_mg_rec(add=1): if_idx=%u, dev=%s, port=%s, gaddr=0x%08x%08x%08x%08x, filter=%u, compat=%u, nsrc=%u\n", rec->if_idx, dev->name, port->name,
				ip6_32[0], ip6_32[1], ip6_32[2], ip6_32[3],
				rec->filter_mode, rec->compat_mode, rec->nsrc
			);
		}
		#endif
	}
	/* debug prints */
	#if 0
	else {
		if (rec->gaddr.type == IPV4)
			printk("brc_add_del_mg_rec(add=0): if_idx=%u, dev=%s, port=%s, gaddr=0x%08x\n", rec->if_idx, dev->name, port->name, rec->gaddr.addr.ip4.s_addr);
		else {
			__be32 *ip6_32 = rec->gaddr.addr.ip6.s6_addr32;
			printk("brc_add_del_mg_rec(add=0): if_idx=%u, dev=%s, port=%s, gaddr=0x%08x%08x%08x%08x\n", rec->if_idx, dev->name, port->name,
				ip6_32[0], ip6_32[1], ip6_32[2], ip6_32[3]
			);
		}
	}
	#endif

	rtnl_unlock();
	err = brc_send_simple_command(dev_net(dev), request);
	rtnl_lock();

	return err;

brc_add_del_mg_rec_put_failure:
	kfree_skb(request);
	return -ENOMEM;
}
/* } seamless-ovs */

static struct net_bridge_port * brc_port_get_rcu(const struct net_device *dev)
{
	struct vport* ret = (struct vport *) rcu_dereference(dev->rx_handler_data);
	return (struct net_bridge_port *) ret->brcompat_data;
}

static int brc_get_bridge_info(struct net_device *dev,
			       struct __bridge_info __user *ub)
{
	int ret;
	struct __bridge_info b;
	unsigned long u_value;
	u8 *prio = (u8 *)&u_value;
	u8 *bridge_id = (u8 *)&b.bridge_id;

	memset(&b, 0, sizeof(struct __bridge_info));

	ret = brc_get_ulong_val_cmd(dev, BRC_GENL_C_GET_BRIDGE_PRIORITY, &u_value);
	if (ret < 0)
		return ret;

	bridge_id[0] = prio[1];
	bridge_id[1] = prio[0];
	memcpy(bridge_id + 2, dev->dev_addr, ETH_ALEN);

	ret = brc_get_ulong_val_cmd(dev, BRC_GENL_C_GET_BRIDGE_STP_STATE, &u_value);
	if (ret < 0)
		return ret;

	b.stp_enabled = (u8)u_value;

	if (copy_to_user(ub, &b, sizeof(struct __bridge_info)))
		return -EFAULT;

	return 0;
}

static int brc_get_port_info(struct net_device *dev,
			       struct __port_info __user *up, int index)
{
	struct __port_info p;

	memset(&p, 0, sizeof(struct __port_info));

	if (copy_to_user(up, &p, sizeof(struct __port_info)))
		return -EFAULT;

	return 0;
}

static int brc_get_port_list(struct net_device *dev, int __user *uindices,
			     int num)
{
	int retval;

	rtnl_unlock();
	retval = brc_get_indices(dev_net(dev), BRC_GENL_C_GET_PORTS, dev->name,
				 uindices, num);
	rtnl_lock();

	return retval;
}

/*
 * Format up to a page worth of forwarding table entries
 * buf         -- where to copy result
 * maxnum      -- maximum number of entries desired
 *                (limited to a page for sanity)
 * offset      -- number of records to skip
 * is_user_buf -- need copy_to_user
 */
static int brc_get_fdb_entries(struct net_device *dev, void *buf,
			       unsigned long maxnum, unsigned long offset, bool is_user_buf)
{
	struct nlattr *attrs[BRC_GENL_A_MAX + 1];
	struct sk_buff *request, *reply;
	int retval;
	int len;

	/* Clamp size to PAGE_SIZE, test maxnum to avoid overflow */
	if (maxnum > PAGE_SIZE/sizeof(struct __fdb_entry))
		maxnum = PAGE_SIZE/sizeof(struct __fdb_entry);

	request = brc_make_request(BRC_GENL_C_FDB_QUERY, dev->name, NULL);
	if (!request)
		return -ENOMEM;
	if (nla_put_u64_64bit(request, BRC_GENL_A_FDB_COUNT, maxnum, BRC_GENL_A_PAD) ||
	    nla_put_u64_64bit(request, BRC_GENL_A_FDB_SKIP, offset, BRC_GENL_A_PAD))
		goto nla_put_failure;

	dev_hold(dev);
	rtnl_unlock();
	reply = brc_send_command(dev_net(dev), request, attrs);
	retval = PTR_ERR(reply);
	if (IS_ERR(reply))
		goto exit;

	retval = -nla_get_u32(attrs[BRC_GENL_A_ERR_CODE]);
	if (retval < 0)
		goto exit_free_skb;

	retval = -EINVAL;
	if (!attrs[BRC_GENL_A_FDB_DATA])
		goto exit_free_skb;
	len = nla_len(attrs[BRC_GENL_A_FDB_DATA]);
	if (len % sizeof(struct __fdb_entry) ||
	    len / sizeof(struct __fdb_entry) > maxnum)
		goto exit_free_skb;

	retval = len / sizeof(struct __fdb_entry);
	if (is_user_buf) {
		if (copy_to_user(buf, nla_data(attrs[BRC_GENL_A_FDB_DATA]), len))
			retval = -EFAULT;
	} else {
		memcpy(buf, nla_data(attrs[BRC_GENL_A_FDB_DATA]), len);
	}

exit_free_skb:
	kfree_skb(reply);
exit:
	rtnl_lock();
	dev_put(dev);
	return retval;

nla_put_failure:
	kfree_skb(request);
	return -ENOMEM;
}

static int brc_set_ulong_val_cmd(struct net_device *dev, int oper, unsigned long param)
{
	struct sk_buff *request;
	int err;

	request = brc_make_request(oper, dev->name, NULL);
	if (!request)
		return -ENOMEM;
	if (nla_put_u64_64bit(request, BRC_GENL_A_ULONG_VAL, param, BRC_GENL_A_PAD))
		goto nla_put_failure;

	rtnl_unlock();
	err = brc_send_simple_command(dev_net(dev), request);
	rtnl_lock();

	return err;

nla_put_failure:
	kfree_skb(request);
	return -ENOMEM;
}

static int brc_get_ulong_val_cmd(struct net_device *dev, int oper, unsigned long *uvalue)
{
	return brc_get_ulong_val_cmd_with_net(dev_net(dev), dev->name, oper, uvalue);
}

static int brc_get_ulong_val_cmd_with_net(struct net *net, const char *bridge, int oper, unsigned long *uvalue)
{
	struct nlattr *attrs[BRC_GENL_A_MAX + 1];
	struct sk_buff *request, *reply;
	int ret;

	request = brc_make_request(oper, bridge, NULL);
	if (!request)
		return -ENOMEM;

	reply = brc_send_command(net, request, attrs);
	ret = PTR_ERR(reply);
	if (IS_ERR(reply))
		goto exit;

	ret = -nla_get_u32(attrs[BRC_GENL_A_ERR_CODE]);
	if (ret < 0)
		goto exit_free_skb;

	if (!attrs[BRC_GENL_A_GET_ULONG]) {
		ret = -EINVAL;
		goto exit_free_skb;
	}

	*uvalue = nla_get_u32(attrs[BRC_GENL_A_GET_ULONG]);

exit_free_skb:
	kfree_skb(reply);
exit:
	return ret;
}

/* Set router port ioctl request */
static int brc_mc_snoop_set_router_port(struct net_device *br_dev, struct ifreq *rq)
{
	struct brc_router_port mcs_rp;
	struct net_device *p_dev;
	struct sk_buff *request;
	int err;

	if (copy_from_user((void *)&mcs_rp, rq->ifr_data, sizeof(struct brc_router_port)))
		return -EFAULT;

	p_dev = dev_get_by_index(dev_net(br_dev), mcs_rp.if_index);
	if (p_dev == NULL)
		return -EINVAL;

	request = brc_make_request(BRC_GENL_C_SET_MCSNOOP_ROUT_PORT, br_dev->name, p_dev->name);
	if (!request){
		dev_put(p_dev);
		return -ENOMEM;
	}

	if (nla_put_u64_64bit(request, BRC_GENL_A_ULONG_VAL, mcs_rp.type, BRC_GENL_A_PAD))
		goto nla_put_failure;
	if (nla_put_u64_64bit(request, BRC_GENL_A_FDB_COUNT, mcs_rp.expires, BRC_GENL_A_PAD))
		goto nla_put_failure;

	rtnl_unlock();
	err = brc_send_simple_command(dev_net(br_dev), request);
	rtnl_lock();
	dev_put(p_dev);
	return err;

nla_put_failure:
	dev_put(p_dev);
	kfree_skb(request);
	return -ENOMEM;
}

/* Legacy ioctl's through SIOCDEVPRIVATE.  Called with rtnl_lock. */
static int old_dev_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	unsigned long args[4];

	if (copy_from_user(args, rq->ifr_data, sizeof(args)))
		return -EFAULT;

	switch (args[0]) {
	case BRCTL_ADD_IF:
		return brc_add_del_port(dev, args[1], 1);
	case BRCTL_DEL_IF:
		return brc_add_del_port(dev, args[1], 0);

	case BRCTL_GET_BRIDGE_INFO:
		return brc_get_bridge_info(dev, (struct __bridge_info __user *)args[1]);

	case BRCTL_GET_PORT_INFO:
		return brc_get_port_info(dev, (struct __port_info __user *)args[1], args[2]);

	case BRCTL_GET_PORT_LIST:
		return brc_get_port_list(dev, (int __user *)args[1], args[2]);

	case BRCTL_GET_FDB_ENTRIES:
		return brc_get_fdb_entries(dev, (void __user *)args[1],
					   args[2], args[3], true);
	case BRCTL_SET_AGEING_TIME:
		return brc_set_ulong_val_cmd(dev, BRC_GENL_C_SET_AGEING_TIME, args[1] / 100);

	case BRCTL_SET_BRIDGE_FORWARD_DELAY:
		return brc_set_ulong_val_cmd(dev, BRC_GENL_C_SET_BRIDGE_FORWARD_DELAY, args[1] / 100);

	case BRCTL_SET_BRIDGE_HELLO_TIME:
		return brc_set_ulong_val_cmd(dev, BRC_GENL_C_SET_BRIDGE_HELLO_TIME, args[1] / 100);

	case BRCTL_SET_BRIDGE_MAX_AGE:
		return brc_set_ulong_val_cmd(dev, BRC_GENL_C_SET_BRIDGE_MAX_AGE, args[1] / 100);

	case BRCTL_SET_BRIDGE_PRIORITY:
		return brc_set_ulong_val_cmd(dev, BRC_GENL_C_SET_BRIDGE_PRIORITY, args[1]);

	case BRCTL_SET_BRIDGE_STP_STATE:
		return brc_set_ulong_val_cmd(dev, BRC_GENL_C_SET_BRIDGE_STP_STATE, args[1]);
	}

	return -EOPNOTSUPP;
}

/* Called with the rtnl_lock. */
static int brc_dev_ioctl(struct net_device *dev, struct ifreq *rq, void __user *data, int cmd)
{
	int err;

	switch (cmd) {
	case SIOCDEVPRIVATE:
		err = old_dev_ioctl(dev, rq, cmd);
		break;

	case SIOCBRADDIF:
		return brc_add_del_port(dev, rq->ifr_ifindex, 1);
	case SIOCBRDELIF:
		return brc_add_del_port(dev, rq->ifr_ifindex, 0);
	case SIOCBRMGADD:
	case SIOCBRMGDEL:
		return brc_add_del_mg_rec(dev, rq->ifr_data, (cmd == SIOCBRMGADD));
	case SIOCBRSETROUTERPORT:
		return brc_mc_snoop_set_router_port(dev, rq);
	case SIOCBRENABLESNOOPING:
	{
		bool brc_snooping_enabled;

		if (copy_from_user((void *) &brc_snooping_enabled, rq->ifr_data, sizeof(bool)))
			return -EFAULT;

		return brc_set_ulong_val_cmd(dev, BRC_GENL_C_SET_BRIDGE_MULTICAST_SNOOPING, brc_snooping_enabled ? 1 : 0);
	}
	default:
		err = -EOPNOTSUPP;
		break;
	}

	return err;
}

/* Called with the rtnl_lock. */
static int brc_dev_mac_addr(struct net_device *dev, void *p)
{
	struct sk_buff  *request;
	int              err;
	struct sockaddr *addr = p;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	/* Here we suppose that there shouldn't be extensive contention on locking 
	 * brc_addbr_lock - we'll aquire it soon */
	for (;;) {
		if (mutex_trylock(&brc_addbr_lock))
			break;
		
		/* Failed to lock brc_addbr_lock - it must be locked in bridge adding handler */
		mutex_lock(&brc_name_lock);
		if (0 == strcmp(bridge_name, dev->name)) {
			/* This bridge is in process of addition via brctl addbr command - we should skip
			 * provisioning of mac address for this bridge to db to avoid deadlock, because
			 * when bridge is added ovs configures its mac address via ioctl at the same time.
			 * Though we shouldn't keep this mac address in db because it's default address for
			 * ovs bridge.
			 */
			mutex_unlock(&brc_name_lock);
			return 0;
		}

		/* mac is for some bridge which is not in process of addition - lets try to lock 
		 * brc_addbr_lock one more time */
		mutex_unlock(&brc_name_lock);
		msleep(100);
	}

	/* We acquired the brc_addbr_lock - we can send mac to userspace safely */
	request = brc_make_request(BRC_GENL_C_SET_MAC_ADDR, dev->name, NULL);
	if (!request) {
		mutex_unlock(&brc_addbr_lock);
		return -ENOMEM;
	}

	if (nla_put(request, BRC_GENL_A_MAC_ADDR, ETH_ALEN, addr->sa_data))
		goto brc_dev_mac_addr_put_failure;

	rtnl_unlock();
	err = brc_send_simple_command(dev_net(dev), request);
	rtnl_lock();

	mutex_unlock(&brc_addbr_lock);
	return err;

brc_dev_mac_addr_put_failure:
	mutex_unlock(&brc_addbr_lock);
	kfree_skb(request);
	return -ENOMEM;
}

/* Called with the rtnl_lock. */
static int brc_dev_mtu(struct net_device *dev, int mtu)
{
	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	return brc_set_ulong_val_cmd(dev, BRC_GENL_C_SET_MTU, mtu);
}

/* Called with the rtnl_lock. */
static int brc_dev_sysfs(struct net_device *dev, unsigned long *ul_value, int cmd, int oper)
{
	int err = 0;
#if IS_ENABLED(CONFIG_BRIDGE)
	struct vport *vport = NULL;
	if (netif_is_ovs_master(dev))
		vport = ovs_internal_dev_get_vport(dev);
	else if (netif_is_ovs_port(dev))
		vport = ovs_netdev_get_vport(dev);
#endif

	if (oper == GET_PARAMETER)
	{
		if (netif_is_ovs_master(dev))
		{
			switch(cmd)
			{
				case IFLA_BR_AGEING_TIME:
					*ul_value = BRC_DEFAULT_MAC_AGING_TIME;
					break;
				case IFLA_BR_FORWARD_DELAY:
					*ul_value = BRC_STP_DEFAULT_FWD_DELAY;
					break;
				case IFLA_BR_HELLO_TIME:
					*ul_value = BRC_STP_DEFAULT_HELLO_TIME;
					break;
				case IFLA_BR_MAX_AGE:
					*ul_value = BRC_STP_DEFAULT_MAX_AGE;
					break;
				case IFLA_BR_MCAST_SNOOPING:
					return brc_get_ulong_val_cmd(dev, BRC_GENL_C_GET_BRIDGE_MULTICAST_SNOOPING, ul_value);
#if IS_ENABLED(CONFIG_BRIDGE)
				case IFLA_BR_MCAST_LAST_MEMBER_CNT:
					if (vport && vport->brcompat_data)
						br_compat_multicast_get_last_member_cnt(vport->brcompat_data, ul_value);
					break;
				case IFLA_BR_MCAST_LAST_MEMBER_INTVL:
					if (vport && vport->brcompat_data)
						br_compat_multicast_get_last_member_intvl(vport->brcompat_data, ul_value);
					break;
				case IFLA_BR_MCAST_MEMBERSHIP_INTVL:
					if (vport && vport->brcompat_data)
						br_compat_multicast_get_membership_intvl(vport->brcompat_data, ul_value);
					break;
				case IFLA_BR_MCAST_QUERIER:
					if (vport && vport->brcompat_data)
						br_compat_multicast_get_querier(vport->brcompat_data, ul_value);
					break;
				case IFLA_BR_MCAST_QUERY_INTVL:
					if (vport && vport->brcompat_data)
						br_compat_multicast_get_query_intvl(vport->brcompat_data, ul_value);
					break;
				case IFLA_BR_MCAST_QUERY_RESPONSE_INTVL:
					if (vport && vport->brcompat_data)
						br_compat_multicast_get_query_response_intvl(vport->brcompat_data, ul_value);
					break;
				case IFLA_BR_MCAST_QUERY_USE_IFADDR:
					if (vport && vport->brcompat_data)
						br_compat_multicast_get_query_use_ifaddr(vport->brcompat_data, ul_value);
					break;
				case IFLA_BR_MCAST_IGMP_VERSION:
					if (vport && vport->brcompat_data)
						br_compat_multicast_get_igmp_version(vport->brcompat_data, ul_value);
					break;
				case IFLA_BR_MCAST_MLD_VERSION:
					if (vport && vport->brcompat_data)
						br_compat_multicast_get_mld_version(vport->brcompat_data, ul_value);
					break;
#endif
				case IFLA_BR_PRIORITY:
					*ul_value = BRC_STP_DEFAULT_BRIDGE_PRIORITY;
					break;
				case IFLA_BR_STP_STATE:
					*ul_value = 0;
					break;
				default:
					return brc_get_ulong_val_cmd(dev, cmd, ul_value);
			}
		}
		else if (netif_is_ovs_port(dev))
		{
			switch(cmd)
			{
				case IFLA_BRPORT_COST:
					*ul_value = BRC_STP_PATH_COST;
					break;
#if IS_ENABLED(CONFIG_BRIDGE)
				case IFLA_BRPORT_FAST_LEAVE:
					if (vport && vport->brcompat_data)
						br_compat_get_port_flag(vport->brcompat_data, ul_value, BR_MULTICAST_FAST_LEAVE);
					break;
				case IFLA_BRPORT_MODE:
					if (vport && vport->brcompat_data)
						br_compat_get_port_flag(vport->brcompat_data, ul_value, BR_HAIRPIN_MODE);
					break;
#endif
				case IFLA_BRPORT_NO:
					return brc_get_ulong_val_cmd(dev, BRC_GENL_C_GET_PORT_PORT_NO, ul_value);
				case IFLA_BRPORT_STATE:
					*ul_value = 0;
					break;
				default:
					return brc_get_ulong_val_cmd(dev, cmd, ul_value);
			}
		}
	}
	else if (oper == SET_PARAMETER)
	{
		if (netif_is_ovs_master(dev))
		{
			switch (cmd)
			{
				case IFLA_BR_AGEING_TIME:
					return brc_set_ulong_val_cmd(dev, BRC_GENL_C_SET_AGEING_TIME, *ul_value);
				case IFLA_BR_FORWARD_DELAY:
				case IFLA_BR_HELLO_TIME:
				case IFLA_BR_MAX_AGE:
					err = -EOPNOTSUPP;
					break;
				case IFLA_BR_MCAST_SNOOPING:
					err = brc_set_ulong_val_cmd(dev, BRC_GENL_C_SET_BRIDGE_MULTICAST_SNOOPING, *ul_value);
#if IS_ENABLED(CONFIG_BRIDGE)
					if (vport && vport->brcompat_data)
						br_compat_multicast_toggle(vport->brcompat_data, !!(*ul_value));
#endif
					break;
#if IS_ENABLED(CONFIG_BRIDGE)
				case IFLA_BR_MCAST_LAST_MEMBER_CNT:
					if (vport && vport->brcompat_data)
						br_compat_multicast_set_last_member_cnt(vport->brcompat_data, *ul_value);
					break;
				case IFLA_BR_MCAST_LAST_MEMBER_INTVL:
					if (vport && vport->brcompat_data)
						br_compat_multicast_set_last_member_intvl(vport->brcompat_data, *ul_value);
					break;
				case IFLA_BR_MCAST_MEMBERSHIP_INTVL:
					if (vport && vport->brcompat_data)
						br_compat_multicast_set_membership_intvl(vport->brcompat_data, *ul_value);
					break;
				case IFLA_BR_MCAST_QUERIER:
					if (vport && vport->brcompat_data)
						br_compat_multicast_set_querier(vport->brcompat_data, !!(*ul_value));
					break;
				case IFLA_BR_MCAST_QUERY_INTVL:
					if (vport && vport->brcompat_data)
						br_compat_multicast_set_query_intvl(vport->brcompat_data, *ul_value);
					break;
				case IFLA_BR_MCAST_QUERY_RESPONSE_INTVL:
					if (vport && vport->brcompat_data)
						br_compat_multicast_set_query_response_intvl(vport->brcompat_data, *ul_value);
					break;
				case IFLA_BR_MCAST_QUERY_USE_IFADDR:
					if (vport && vport->brcompat_data)
						br_compat_multicast_set_query_use_ifaddr(vport->brcompat_data, !!(*ul_value));
					break;
				case IFLA_BR_MCAST_IGMP_VERSION:
					if (vport && vport->brcompat_data)
						br_compat_multicast_set_igmp_version(vport->brcompat_data, *ul_value);
					break;
				case IFLA_BR_MCAST_MLD_VERSION:
					if (vport && vport->brcompat_data)
						br_compat_multicast_set_mld_version(vport->brcompat_data, *ul_value);
					break;
#endif
				case IFLA_BR_PRIORITY:
				case IFLA_BR_STP_STATE:
					err = -EOPNOTSUPP;
					break;
				default:
					return brc_set_ulong_val_cmd(dev, cmd, *ul_value);
			}
		}
		else if (netif_is_ovs_port(dev))
		{
			switch (cmd)
			{
				case IFLA_BRPORT_COST:
					err = -EOPNOTSUPP;
					break;
				case IFLA_BRPORT_FAST_LEAVE:
					dev_hold(dev);
					err = brc_set_ulong_val_cmd(dev, BRC_GENL_C_SET_PORT_MC_SNOOPING_FLOOD_REPORTS, !*ul_value);
#if IS_ENABLED(CONFIG_BRIDGE)
					if (likely(dev->priv_flags & IFF_OVS_DATAPATH)) {
						if (vport && vport->brcompat_data)
							br_compat_set_port_flag(vport->brcompat_data, *ul_value, BR_MULTICAST_FAST_LEAVE);
					}
#endif
					dev_put(dev);
					break;
				case IFLA_BRPORT_MODE:
					dev_hold(dev);
					err = brc_set_ulong_val_cmd(dev, BRC_GENL_C_SET_PORT_HAIRPIN_MODE, *ul_value);
#if IS_ENABLED(CONFIG_BRIDGE)
					if (vport && vport->brcompat_data)
						br_compat_set_port_flag(vport->brcompat_data, *ul_value, BR_HAIRPIN_MODE);
#endif
					dev_put(dev);
					break;
				case IFLA_BRPORT_NO:
				case IFLA_BRPORT_STATE:
					err = -EOPNOTSUPP;
					break;
				default:
					return brc_set_ulong_val_cmd(dev, cmd, *ul_value);
			}
		}
	}
	else
		err = -1;

	return err;
}

/* Called with the rtnl_lock. */
static int brc_dev_sysfs_string(struct net_device *dev, char *ustring, int cmd)
{
	int err = 0;

	switch (cmd) {
	case BRC_GENL_C_GET_BRIDGE_ROOT_ID:
		return brc_get_string(dev, BRC_GENL_C_GET_BRIDGE_ROOT_ID, ustring);
	case BRC_GENL_C_GET_BRIDGE_BY_PORT: {
		return brc_get_string(dev, BRC_GENL_C_GET_BRIDGE_BY_PORT, ustring);
	}

	default:
		err = -1;
		break;
	}

	return err;
}

static void brc_dev_init(struct vport *vport)
{
	if (vport && vport->brcompat_data)
		br_compat_multicast_init_stats(vport->brcompat_data);
}

static void brc_dev_open(struct vport *vport)
{
	if (vport && vport->brcompat_data)
		br_compat_multicast_open(vport->brcompat_data);
}

static void brc_dev_stop(struct vport *vport)
{
	if (vport && vport->brcompat_data)
		br_compat_multicast_stop(vport->brcompat_data);
}

static int brc_dev_set_mtu_set_by_user(struct net_device *dev, int is_set_by_user)
{
	return br_compat_set_mtu_set_by_user(dev, is_set_by_user);
}

static int brc_multicast_add_group(struct vport *vport, struct br_ip *group, unsigned char *mac)
{
	void *br_mport = NULL;
	void *mport = NULL;

	if (!vport || !vport->brcompat_data)
		return -1;

	if (vport->type == OVS_VPORT_TYPE_INTERNAL) {
		br_mport = vport->brcompat_data;
	} else {
		mport = vport->brcompat_data;
	}

	return br_compat_multicast_add_group(br_mport, mport, group, mac);
}

static int brc_multicast_del_group(struct vport *vport, struct br_ip *group, unsigned char *mac)
{
	void *br_mport = NULL;
	void *mport = NULL;

	if (!vport || !vport->brcompat_data)
		return -1;

	if (vport->type == OVS_VPORT_TYPE_INTERNAL) {
		br_mport = vport->brcompat_data;
	} else {
		mport = vport->brcompat_data;
	}

	return br_compat_multicast_leave_group(br_mport, mport, group, mac);
}

static int brc_genl_query(struct sk_buff *skb, struct genl_info *info)
{
	int err = -EINVAL;
	struct sk_buff *ans_skb;
	void *data;

	ans_skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!ans_skb)
		return -ENOMEM;

	data = genlmsg_put_reply(ans_skb, info, &brc_genl_family,
				 0, BRC_GENL_C_QUERY_MC);
	if (data == NULL) {
		err = -ENOMEM;
		goto err;
	}
	if (nla_put_u32(ans_skb, BRC_GENL_A_MC_GROUP, GROUP_ID(&brc_mc_group)))
		goto nla_put_failure;

	genlmsg_end(ans_skb, data);
	return genlmsg_reply(ans_skb, info);

err:
nla_put_failure:
	kfree_skb(ans_skb);
	return err;
}

/* Attribute policy: what each attribute may contain.  */
static struct nla_policy brc_genl_policy[BRC_GENL_A_MAX + 1] = {
	[BRC_GENL_A_ERR_CODE] = { .type = NLA_U32 },
	[BRC_GENL_A_FDB_DATA] = { .type = NLA_UNSPEC },
};

static int brc_genl_dp_result(struct sk_buff *skb, struct genl_info *info)
{
	unsigned long int flags;
	int err;

	if (!info->attrs[BRC_GENL_A_ERR_CODE])
		return -EINVAL;

	skb = skb_clone(skb, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	spin_lock_irqsave(&brc_lock, flags);
	if (brc_seq == info->snd_seq) {
		brc_seq++;

		kfree_skb(brc_reply);
		brc_reply = skb;

		complete(&brc_done);
		err = 0;
	} else {
		kfree_skb(skb);
		err = -ESTALE;
	}
	spin_unlock_irqrestore(&brc_lock, flags);

	return err;
}

static struct genl_ops brc_genl_ops[] = {
	{ .cmd = BRC_GENL_C_QUERY_MC,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privelege. */
	  .policy = NULL,
	  .doit = brc_genl_query,
	},
	{ .cmd = BRC_GENL_C_DP_RESULT,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privelege. */
	  .policy = brc_genl_policy,
	  .doit = brc_genl_dp_result,
#ifdef HAVE_GENL_VALIDATE_FLAGS
	  .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
#endif
	},
};

static struct genl_family brc_genl_family = {
	.hdrsize = 0,
	.name = BRC_GENL_FAMILY_NAME,
	.version = 1,
	.maxattr = BRC_GENL_A_MAX,
	.netnsok = true,
	.parallel_ops = true,
	.ops = brc_genl_ops,
	.n_ops = ARRAY_SIZE(brc_genl_ops),
	.mcgrps = &brc_mc_group,
	.n_mcgrps = 1,
	.module = THIS_MODULE,
};

static struct sk_buff *brc_send_command(struct net *net,
					struct sk_buff *request,
					struct nlattr **attrs)
{
	unsigned long int flags;
	struct sk_buff *reply;
	int error;

	mutex_lock(&brc_serial);

	brc_netlink_flg = true;

	/* Increment sequence number first, so that we ignore any replies
	 * to stale requests. */
	spin_lock_irqsave(&brc_lock, flags);
	nlmsg_hdr(request)->nlmsg_seq = ++brc_seq;
	init_completion(&brc_done);
	spin_unlock_irqrestore(&brc_lock, flags);

	nlmsg_end(request, nlmsg_hdr(request));

	/* Send message. */
	error = genlmsg_multicast_netns(&brc_genl_family, net, request, 0,
					GROUP_ID(&brc_mc_group), GFP_KERNEL);
	if (error < 0)
		goto error;

	/* Wait for reply. */
	error = -ETIMEDOUT;
	if (!wait_for_completion_timeout(&brc_done, BRC_TIMEOUT)) {
		pr_warn("timed out waiting for userspace\n");
		goto error;
	}

	/* Grab reply. */
	spin_lock_irqsave(&brc_lock, flags);
	reply = brc_reply;
	brc_reply = NULL;
	spin_unlock_irqrestore(&brc_lock, flags);

	brc_netlink_flg = false;

	mutex_unlock(&brc_serial);

	/* Re-parse message.  Can't fail, since it parsed correctly once
	 * already. */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,1,21)
	error = genlmsg_parse(nlmsg_hdr(reply), &brc_genl_family,
			    attrs, BRC_GENL_A_MAX, brc_genl_policy, NULL);
#else
	error = genlmsg_parse_deprecated(nlmsg_hdr(reply), &brc_genl_family,
			    attrs, BRC_GENL_A_MAX, brc_genl_policy, NULL);
#endif
	WARN_ON(error);

	return reply;

error:
	mutex_unlock(&brc_serial);
	return ERR_PTR(error);
}

static int brc_br_bridge_setup(struct vport *vport, int add)
{
	if (!vport)
		return -EINVAL;

	if (add) {
		if(!try_module_get(THIS_MODULE)) {
			pr_warn("Impossible to increment reference count!\n");
		}
		return br_compat_bridge_create(vport->dev, &vport->brcompat_data);
	}
	else
	{
		module_put(THIS_MODULE);
		br_compat_multicast_dev_del(vport->brcompat_data);
		vport->brcompat_data = NULL;
		return 0;
	}

	return -EOPNOTSUPP;
}

static int brc_br_port_setup(struct vport *br_vport, struct vport *vport, int add)
{
	if (!vport)
		return -EINVAL;

	if (add)
	{
		if (!br_vport || !br_vport->brcompat_data)
			return -EINVAL;
		

		return br_compat_bridge_port_create(br_vport->brcompat_data, vport->dev, &vport->brcompat_data);
	}
	else
	{
		br_compat_multicast_disable_port(vport->brcompat_data);
		br_compat_multicast_del_port(vport->brcompat_data);
		vport->brcompat_data = NULL;
		return 0;
	}

	return -EOPNOTSUPP;
}

static int brc_br_port_set_param(struct vport *vport, struct net_device *dev, struct nlattr *data[])
{
	int err = 0;
	u8 val;

	if (!vport || !dev || !data)
		return 0;

	dev_hold(dev);

	if (data[IFLA_BRPORT_FAST_LEAVE]) {
		val = nla_get_u8(data[IFLA_BRPORT_FAST_LEAVE]);

		err = brc_set_ulong_val_cmd(dev, BRC_GENL_C_SET_PORT_MC_SNOOPING_FLOOD_REPORTS, !val);
		if (err)
			goto err;

		if (unlikely((dev->priv_flags & IFF_OVS_DATAPATH) == 0)) {
			err = -ENODEV;
			goto err;
		}

		err = br_compat_set_port_flag(vport->brcompat_data, val, BR_MULTICAST_FAST_LEAVE);
	}

	if (data[IFLA_BRPORT_MODE]) {
		val = nla_get_u8(data[IFLA_BRPORT_MODE]);

		err = brc_set_ulong_val_cmd(dev, BRC_GENL_C_SET_PORT_HAIRPIN_MODE, val);
		if (err)
			goto err;

		if (unlikely((dev->priv_flags & IFF_OVS_DATAPATH) == 0)) {
			err = -ENODEV;
			goto err;
		}

		err = br_compat_set_port_flag(vport->brcompat_data, val, BR_HAIRPIN_MODE);
	}

err:
	dev_put(dev);
	return err;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
static int brc_br_port_slave_changelink(struct vport *vport,
				    struct net_device *brdev,
				    struct net_device *dev,
				    struct nlattr *tb[],
				    struct nlattr *data[])
{
	return brc_br_port_set_param(vport, dev, data);
}
static int br_validate(struct nlattr *tb[], struct nlattr *data[])
{
	return br_compat_link_ops.validate(tb, data);
}

static int br_dev_newlink(struct net *src_net, struct net_device *dev,
			  struct nlattr *tb[], struct nlattr *data[])
{
	if (dev->priv_flags & IFF_OPENVSWITCH)
		return br_ovs_link_ops->newlink ? br_ovs_link_ops->newlink(src_net, dev, tb, data) : -EOPNOTSUPP;
	else
		return br_compat_link_ops.newlink(src_net, dev, tb, data);
}

static int br_changelink(struct net_device *brdev, struct nlattr *tb[],
			 struct nlattr *data[])
{
	if (brdev->priv_flags & IFF_OPENVSWITCH)
		return br_ovs_link_ops->changelink ? br_ovs_link_ops->changelink(brdev, tb, data) : -EOPNOTSUPP;
	return br_compat_link_ops.changelink(brdev, tb, data);
}
static int br_port_slave_changelink(struct net_device *brdev, struct net_device *dev, struct nlattr *tb[], struct nlattr *data[])
{
	if (brdev->priv_flags & IFF_OPENVSWITCH) {
		if (dev->priv_flags & IFF_OVS_DATAPATH)
			return br_ovs_link_ops->slave_changelink ? br_ovs_link_ops->slave_changelink(brdev, dev, tb, data) : -EOPNOTSUPP;
		return -EOPNOTSUPP;
	}
	return br_compat_link_ops.slave_changelink(brdev, dev, tb, data);
}
#else
static int brc_br_port_slave_changelink(struct vport *vport,
				    struct net_device *brdev,
				    struct net_device *dev,
				    struct nlattr *tb[],
				    struct nlattr *data[],
				    struct netlink_ext_ack *extack)
{
	return brc_br_port_set_param(vport, dev, data);
}
static int br_validate(struct nlattr *tb[], struct nlattr *data[],
		       struct netlink_ext_ack *extack)
{
	return br_compat_link_ops.validate(tb, data, extack);
}

static int br_dev_newlink(struct net *src_net, struct net_device *dev,
			  struct nlattr *tb[], struct nlattr *data[],
			  struct netlink_ext_ack *extack)
{
	if (dev->priv_flags & IFF_OPENVSWITCH)
		return br_ovs_link_ops->newlink ? br_ovs_link_ops->newlink(src_net, dev, tb, data, extack) : -EOPNOTSUPP;
	else
		return br_compat_link_ops.newlink(src_net, dev, tb, data, extack);
}

static int br_changelink(struct net_device *brdev, struct nlattr *tb[],
			 struct nlattr *data[],
			 struct netlink_ext_ack *extack)
{
	if (brdev->priv_flags & IFF_OPENVSWITCH)
		return br_ovs_link_ops->changelink ? br_ovs_link_ops->changelink(brdev, tb, data, extack) : -EOPNOTSUPP;
	return br_compat_link_ops.changelink(brdev, tb, data, extack);
}
static int br_port_slave_changelink(struct net_device *brdev, struct net_device *dev, struct nlattr *tb[], struct nlattr *data[], struct netlink_ext_ack *extack)
{
	if (brdev->priv_flags & IFF_OPENVSWITCH) {
		if (dev->priv_flags & IFF_OVS_DATAPATH)
			return br_ovs_link_ops->slave_changelink ? br_ovs_link_ops->slave_changelink(brdev, dev, tb, data, extack) : -EOPNOTSUPP;
		return -EOPNOTSUPP;
	}
	return br_compat_link_ops.slave_changelink(brdev, dev, tb, data, extack);
}
#endif

static int brc_br_changelink(struct vport *vport, struct nlattr *tb[], struct nlattr *data[])
{
	void *brcompat_data = NULL;

	if (!vport || !data)
		return 0;

	brcompat_data = vport->brcompat_data;

	if (data[IFLA_BR_MCAST_QUERIER]) {
		u8 val = nla_get_u8(data[IFLA_BR_MCAST_QUERIER]);

		br_compat_multicast_set_querier(brcompat_data, val);
	}

	if (data[IFLA_BR_MCAST_SNOOPING]) {
		u8 val = nla_get_u8(data[IFLA_BR_MCAST_SNOOPING]);

		dev_hold(vport->dev);
		brc_set_ulong_val_cmd(vport->dev, BRC_GENL_C_SET_BRIDGE_MULTICAST_SNOOPING, val);
		if (unlikely((vport->dev->priv_flags & IFF_OPENVSWITCH) == 0)) {
			dev_put(vport->dev);
			return -ENODEV;
		}
		dev_put(vport->dev);

		br_compat_multicast_toggle(brcompat_data, val);
	}

	if (data[IFLA_BR_MCAST_IGMP_VERSION]) {
		u8 val = nla_get_u8(data[IFLA_BR_MCAST_IGMP_VERSION]);

		br_compat_multicast_set_igmp_version(brcompat_data, val);
	}

	if (data[IFLA_BR_MCAST_QUERY_USE_IFADDR]) {
		u8 val = nla_get_u8(data[IFLA_BR_MCAST_QUERY_USE_IFADDR]);

		br_compat_multicast_set_query_use_ifaddr(brcompat_data, val);
	}

	if (data[IFLA_BR_MCAST_LAST_MEMBER_CNT]) {
		u32 val = nla_get_u32(data[IFLA_BR_MCAST_LAST_MEMBER_CNT]);

		br_compat_multicast_set_last_member_cnt(brcompat_data, val);
	}

	if (data[IFLA_BR_MCAST_LAST_MEMBER_INTVL]) {
		u64 val = nla_get_u64(data[IFLA_BR_MCAST_LAST_MEMBER_INTVL]);

		br_compat_multicast_set_last_member_intvl(brcompat_data, val);
	}

	if (data[IFLA_BR_MCAST_MEMBERSHIP_INTVL]) {
		u64 val = nla_get_u64(data[IFLA_BR_MCAST_MEMBERSHIP_INTVL]);

		br_compat_multicast_set_membership_intvl(brcompat_data, val);
	}

	if (data[IFLA_BR_MCAST_QUERY_INTVL]) {
		u64 val = nla_get_u64(data[IFLA_BR_MCAST_QUERY_INTVL]);

		br_compat_multicast_set_query_intvl(brcompat_data, val);
	}

	if (data[IFLA_BR_MCAST_QUERY_RESPONSE_INTVL]) {
		u64 val = nla_get_u64(data[IFLA_BR_MCAST_QUERY_RESPONSE_INTVL]);

		br_compat_multicast_set_query_response_intvl(brcompat_data, val);
	}

#if IS_ENABLED(CONFIG_IPV6)
	if (data[IFLA_BR_MCAST_MLD_VERSION]) {
		u8 val = nla_get_u8(data[IFLA_BR_MCAST_MLD_VERSION]);

		br_compat_multicast_set_mld_version(brcompat_data, val);
	}
#endif

	return 0;
}





static int brc_br_setlink(struct vport *vport, struct net_device *dev, struct nlmsghdr *nlh, u16 flags)
{
	int err = 0;
	static const struct nla_policy br_port_policy[IFLA_BRPORT_MAX + 1] = {
		[IFLA_BRPORT_STATE]	= { .type = NLA_U8 },
		[IFLA_BRPORT_COST]	= { .type = NLA_U32 },
		[IFLA_BRPORT_PRIORITY]	= { .type = NLA_U16 },
		[IFLA_BRPORT_MODE]	= { .type = NLA_U8 },
		[IFLA_BRPORT_GUARD]	= { .type = NLA_U8 },
		[IFLA_BRPORT_PROTECT]	= { .type = NLA_U8 },
		[IFLA_BRPORT_FAST_LEAVE]= { .type = NLA_U8 },
		[IFLA_BRPORT_LEARNING]	= { .type = NLA_U8 },
		[IFLA_BRPORT_UNICAST_FLOOD] = { .type = NLA_U8 },
		[IFLA_BRPORT_PROXYARP]	= { .type = NLA_U8 },
		[IFLA_BRPORT_PROXYARP_WIFI] = { .type = NLA_U8 },
		[IFLA_BRPORT_MULTICAST_ROUTER] = { .type = NLA_U8 },
	};
	struct nlattr *protinfo;
	struct nlattr *tb[IFLA_BRPORT_MAX + 1];

	protinfo = nlmsg_find_attr(nlh, sizeof(struct ifinfomsg), IFLA_PROTINFO);
	if (!protinfo)
		return 0;

	err = nla_parse_nested(tb, IFLA_BRPORT_MAX, protinfo, br_port_policy, NULL);
	if (err)
		return err;

	return brc_br_port_set_param(vport, dev, tb);
}

static int brc_br_fill_info(struct vport *vport, struct sk_buff *skb, const struct net_device *br_dev)
{
	if (vport->brcompat_data)
		return br_compat_multicast_fill_info(vport->brcompat_data, skb, br_dev);

	return 0;
}

static int brc_br_fill_ifinfo(struct vport *vport, struct sk_buff *skb, const struct net_device *dev, u32 pid, u32 seq, int event, unsigned int flags)
{
	int ret = 0;
	u8 operstate;
	struct ifinfomsg *hdr;
	struct nlmsghdr *nlh;
	struct net_device *upper_dev;

	if (!skb || !dev)
		return -EINVAL;

	if (vport)
		upper_dev = netdev_master_upper_dev_get((struct net_device *) dev);
    else
		upper_dev = (struct net_device *) dev;

	nlh = nlmsg_put(skb, pid, seq, event, sizeof(*hdr), flags);
	if (nlh == NULL)
		return -EMSGSIZE;

	hdr = nlmsg_data(nlh);
	hdr->ifi_family = AF_BRIDGE;
	hdr->__ifi_pad = 0;
	hdr->ifi_type = dev->type;
	hdr->ifi_index = dev->ifindex;
	hdr->ifi_flags = dev_get_flags(dev);
	hdr->ifi_change = 0;


	operstate = netif_running(dev) ? dev->operstate : IF_OPER_DOWN;
	if (nla_put_string(skb, IFLA_IFNAME, dev->name) ||
		nla_put_u32(skb, IFLA_MASTER, upper_dev->ifindex) ||
		nla_put_u32(skb, IFLA_MTU, dev->mtu) ||
		nla_put_u8(skb, IFLA_OPERSTATE, operstate) ||
		(dev->addr_len &&
		nla_put(skb, IFLA_ADDRESS, dev->addr_len, dev->dev_addr)) ||
		(dev->ifindex != dev_get_iflink(dev) &&
		nla_put_u32(skb, IFLA_LINK, dev_get_iflink(dev)))) {
			ret = -EMSGSIZE;
			goto nla_put_failure;
	}

	if (event == RTM_NEWLINK && vport) {
		struct nlattr *nest
			= nla_nest_start(skb, IFLA_PROTINFO | NLA_F_NESTED);

		if (nest == NULL || (br_compat_multicast_fill_slave_info(vport->brcompat_data, skb, upper_dev, dev) < 0))
			goto nla_put_failure;
		nla_nest_end(skb, nest);
	}


	nlmsg_end(skb, nlh);
	return 0;

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return ret;
}

static int brc_br_port_fill_slave_info(struct vport *vport, struct sk_buff *skb, const struct net_device *br_dev, const struct net_device *dev)
{
	if (vport->brcompat_data)
		return br_compat_multicast_fill_slave_info(vport->brcompat_data, skb, br_dev, dev);

	return 0;
}

static void *brc_br_get_bridge(struct net_device *dev)
{
	struct vport *vport;

	vport = ovs_internal_dev_get_vport(dev);

	if (vport && vport->brcompat_data)
		return vport->brcompat_data;

	return NULL;
}

static bool check_bridge_list(const char *name)
{
	int i;
	for (i = 0; i < size_list; i++) {
		if (!br_list[i])
			break;
		if (br_list[i][0] == '!') {
			if (strcmp(name, &br_list[i][1]) == 0)
				return false;
		} else {
			if (strcmp(name, br_list[i]) == 0)
				return true;
		}
	}
	if (!br_list[0])
		return false;

	if (br_list[0][0] == '*')
		return true;

	return false;
}

#ifdef CONFIG_LTQ_MCAST_SNOOPING
static void brc_mcsnoop_hook(int type, int br_snooping)
{
	struct sk_buff *request;

	if (!brc_net)
		return;

	request = brc_make_request(BRC_GENL_C_SET_MC_SNOOPING_FLAG, NULL, NULL);
	if (!request)
		return;

	if (nla_put_u64_64bit(request, BRC_GENL_A_ULONG_VAL, type, BRC_GENL_A_PAD))
		goto nla_put_failure;
	if (nla_put_u64_64bit(request, BRC_GENL_A_FDB_COUNT, br_snooping, BRC_GENL_A_PAD))
		goto nla_put_failure;

	rtnl_unlock();
	brc_send_simple_command(brc_net, request);
	rtnl_lock();

	return;

nla_put_failure:
	kfree_skb(request);
}
#endif

void br_dev_setup(struct net_device *dev)
{
	if (check_bridge_list(dev->name) && br_ovs_link_ops->setup)
		br_ovs_link_ops->setup(dev);
	else
		br_compat_link_ops.setup(dev);
}


void br_dev_delete(struct net_device *dev, struct list_head *head)
{
	if (dev->priv_flags & IFF_OPENVSWITCH) {
		if (br_ovs_link_ops->dellink)
			br_ovs_link_ops->dellink(dev, head);
	} else
		br_compat_link_ops.dellink(dev, head);
}

static size_t br_get_size(const struct net_device *brdev)
{
	return br_compat_link_ops.get_size(brdev);
}

static int br_fill_info(struct sk_buff *skb, const struct net_device *brdev)
{
	if (brdev->priv_flags & IFF_OPENVSWITCH)
		return br_ovs_link_ops->fill_info ? br_ovs_link_ops->fill_info(skb, brdev) : 0;
	return br_compat_link_ops.fill_info(skb, brdev);
}

static int br_fill_linkxstats(struct sk_buff *skb, const struct net_device *dev, int *prividx, int attr)
{
	if (dev->priv_flags & IFF_OPENVSWITCH)
		return br_ovs_link_ops->fill_linkxstats ? br_ovs_link_ops->fill_linkxstats(skb, dev, prividx, attr) : -EOPNOTSUPP;
	return br_compat_link_ops.fill_linkxstats(skb, dev, prividx, attr);
}

static size_t br_get_linkxstats_size(const struct net_device *dev, int attr)
{
	if (dev->priv_flags & IFF_OPENVSWITCH)
		return br_ovs_link_ops->get_linkxstats_size ? br_ovs_link_ops->get_linkxstats_size(dev, attr) : 0;
	return br_compat_link_ops.get_linkxstats_size(dev, attr);
}


static size_t br_port_get_slave_size(const struct net_device *brdev, const struct net_device *dev)
{
	if (brdev->priv_flags & IFF_OPENVSWITCH && dev->priv_flags & IFF_OVS_DATAPATH)
			return br_ovs_link_ops->get_slave_size ? br_ovs_link_ops->get_slave_size(brdev, dev) : br_compat_link_ops.get_slave_size(brdev, dev);
	return br_compat_link_ops.get_slave_size(brdev, dev);
}

static int br_port_fill_slave_info(struct sk_buff *skb, const struct net_device *brdev, const struct net_device *dev)
{
	if (brdev->priv_flags & IFF_OPENVSWITCH) {
		if (dev->priv_flags & IFF_OVS_DATAPATH)
			return br_ovs_link_ops->fill_slave_info ? br_ovs_link_ops->fill_slave_info(skb, brdev, dev) : 0;
		return 0;
	}
	return br_compat_link_ops.fill_slave_info(skb, brdev, dev);
}

static struct rtnl_link_ops * brc_get_rtnl_link_ops(void)
{
	return br_link_ops;
}

static int __init brc_init(void)
{
	int err;

	pr_info("Open vSwitch Bridge Compatibility\n");

	/* Set the bridge ioctl handler */
	bridge_ioctl_hook = brioctl_get();
	if (!bridge_ioctl_hook) {
		pr_info("error: bridge_ioctl_hook is NULL!\n");
		goto error;
	}
	brioctl_set(brc_ioctl_deviceless_stub);

	/* Set the openvswitch device ioctl handler */
	ovs_dp_ioctl_hook = brc_dev_ioctl;

	/* Set the openvswitch device mac address assignment handler */
	ovs_dp_mac_addr_hook = brc_dev_mac_addr;

	/* Set the openvswitch device mtu assignment handler */
	ovs_dp_mtu_hook = brc_dev_mtu;

	/* Set the openvswitch device add/del port handler */
	ovs_dp_add_del_port_hook = brc_add_del_port_dev;

	/* Set the openvswitch br_changelink handler */
	ovs_dp_br_changelink_hook = brc_br_changelink;

	/* Get net_device address in case it was allocated in rtnl_newlink */
	ovs_dp_br_get_netdev_hook = brc_get_netdev;

	/* Set the openvswitch brc_add_bridge_netlink handler */
	ovs_dp_br_brc_add_bridge_netlink_hook = brc_add_bridge_netlink;

	/* Set the openvswitch brc_del_bridge handler */
	ovs_dp_br_brc_del_bridge_netlink_hook = brc_del_bridge_netlink;

	/* Set the openvswitch br_port_slave_changelink handler */
	ovs_dp_br_port_slave_changelink_hook = brc_br_port_slave_changelink;

	/* Set the openvswitch br_fill_info handler */
	ovs_dp_br_fill_info_hook = brc_br_fill_info;

	/* Set the openvswitch br_fill_info handler */
	ovs_dp_br_fill_ifinfo_hook = brc_br_fill_ifinfo;

	/* Set the openvswitch br_port_fill_slave_info handler */
	ovs_dp_br_port_fill_slave_info_hook = brc_br_port_fill_slave_info;

	/* set the openvswitch linux bridge struct handler */
	ovs_dp_br_bridge_setup = brc_br_bridge_setup;

	/* set the openvswitch linux bridge port handler */
	ovs_dp_br_bridge_port_setup = brc_br_port_setup;

	/* Set the openvswitch br_setlink handler */
	ovs_dp_br_setlink_hook = brc_br_setlink;

	/* Set the br_compat br_get_mtu_set_by_user handler */
	br_compat_get_bridge_hook = brc_br_get_bridge;

	/* Set the openvswitch device sysfs handler */
	ovs_dp_sysfs_hook = brc_dev_sysfs;
	ovs_dp_sysfs_string_hook = brc_dev_sysfs_string;

	ovs_get_fdb_entries = brc_get_fdb_entries;

	ovs_port_get_rcu = brc_port_get_rcu;

	ovs_dp_dev_init = brc_dev_init;
	ovs_dp_dev_open = brc_dev_open;
	ovs_dp_dev_stop = brc_dev_stop;

	ovs_dp_dev_set_mtu_set_by_user = brc_dev_set_mtu_set_by_user;

	ovs_dp_multicast_add_group = brc_multicast_add_group;
	ovs_dp_multicast_del_group = brc_multicast_del_group;

	rtnl_lock();

	br_link_ops = (struct rtnl_link_ops *)rtnl_link_ops_get("bridge");
	memcpy(&br_compat_link_ops, br_link_ops, sizeof(*br_link_ops));
	br_ovs_link_ops = rtnl_link_ops_get("openvswitch");

	br_link_ops->setup = br_dev_setup;
	br_link_ops->validate = br_validate;
	br_link_ops->newlink = br_dev_newlink;
	br_link_ops->changelink = br_changelink;
	br_link_ops->dellink = br_dev_delete;
	br_link_ops->get_size = br_get_size;
	br_link_ops->fill_info = br_fill_info;
	br_link_ops->fill_linkxstats = br_fill_linkxstats;
	br_link_ops->get_linkxstats_size = br_get_linkxstats_size;
	br_link_ops->slave_changelink = br_port_slave_changelink;
	br_link_ops->get_slave_size = br_port_get_slave_size;
	br_link_ops->fill_slave_info = br_port_fill_slave_info;

	/* Set the openvswitch get_rtnl_link_ops handler */
	ovs_dp_get_rtnl_link_ops_hook = brc_get_rtnl_link_ops;

	rtnl_unlock();

#ifdef CONFIG_LTQ_MCAST_SNOOPING
	/* Set multicast snooping hooks */
	ovs_brc_mcsnoop_hook = brc_mcsnoop_hook;
#endif

	/* Randomize the initial sequence number.  This is not a security
	 * feature; it only helps avoid crossed wires between userspace and
	 * the kernel when the module is unloaded and reloaded. */
	brc_seq = prandom_u32();

	/* Register generic netlink family to communicate changes to
	 * userspace. */
	err = genl_register_family(&brc_genl_family);
	if (err)
		goto error;

	return 0;

error:
	pr_emerg("failed to install!\n");
	return err;
}

static void brc_cleanup(void)
{
	/* Unregister ioctl hooks */
	ovs_dp_ioctl_hook = NULL;

	/* Unregister mac address hooks */
	ovs_dp_mac_addr_hook = NULL;

	/* Unregister mtu hooks */
	ovs_dp_mtu_hook = NULL;

	/* Unregister add/del port hooks */
	ovs_dp_add_del_port_hook = NULL;

	/* Unregister br_changelink hooks */
	ovs_dp_br_changelink_hook = NULL;

	/* Unregister net_device address hook */
	ovs_dp_br_get_netdev_hook = NULL;

	/* Unregister br_brc_add_bridge hooks */
	ovs_dp_br_brc_add_bridge_netlink_hook = NULL;

	/* Unregister br_brc_del_bridge hooks */
	ovs_dp_br_brc_del_bridge_netlink_hook = NULL;

	/* Unregister br_port_slave_changelink hooks */
	ovs_dp_br_port_slave_changelink_hook = NULL;

	/* Unregister br_fill_info hooks */
	ovs_dp_br_fill_info_hook = NULL;

	/* Unregister br_port_fill_slave_info hooks */
	ovs_dp_br_port_fill_slave_info_hook = NULL;

	/* Unregister br_setlink hooks */
	ovs_dp_br_setlink_hook = NULL;

	/* set the openvswitch linux bridge struct handler */
	ovs_dp_br_bridge_setup = NULL;

	/* set the openvswitch linux bridge port handler */
	ovs_dp_br_bridge_port_setup = NULL;

	/* Unregister get_rtnl_link_ops hooks */
	ovs_dp_get_rtnl_link_ops_hook = NULL;

	/* Unregister get_mtu_set_by_user hooks */
	br_compat_get_bridge_hook = NULL;

	/* Unregister brc_get_fdb_entries */
	ovs_get_fdb_entries = NULL;

	ovs_port_get_rcu = NULL;

	ovs_dp_dev_init = NULL;

	ovs_dp_dev_open = NULL;

	ovs_dp_dev_stop = NULL;

	ovs_dp_dev_set_mtu_set_by_user = NULL;

	ovs_dp_multicast_add_group = NULL;

	ovs_dp_multicast_del_group = NULL;

	rtnl_lock();
	br_link_ops = (struct rtnl_link_ops *)rtnl_link_ops_get("bridge");
	memcpy(br_link_ops, &br_compat_link_ops, sizeof(*br_link_ops));
	rtnl_unlock();

	/* Back the hook of the linux bridge to socket module */
	brioctl_set(bridge_ioctl_hook);

#ifdef CONFIG_LTQ_MCAST_SNOOPING
	/* Unregister multicast snooping hooks */
	ovs_brc_mcsnoop_hook = NULL;
#endif

	genl_unregister_family(&brc_genl_family);
}

module_init(brc_init);
module_exit(brc_cleanup);

MODULE_DESCRIPTION("Open vSwitch bridge compatibility");
MODULE_AUTHOR("Nicira, Inc.");
MODULE_LICENSE("GPL");

/*
 * Open vSwitch can safely coexist with
 * the Linux bridge module, but it does not make sense to load both bridge and
 * brcompat, so this prevents it.
 */
//BRIDGE_MUTUAL_EXCLUSION;
