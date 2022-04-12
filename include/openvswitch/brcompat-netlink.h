/*
 * Copyright (c) 2008, 2009, 2011 Nicira, Inc.
 *
 * This file is offered under your choice of two licenses: Apache 2.0 or GNU
 * GPL 2.0 or later.  The permission statements for each of these licenses is
 * given below.  You may license your modifications to this file under either
 * of these licenses or both.  If you wish to license your modifications under
 * only one of these licenses, delete the permission text for the other
 * license.
 *
 * ----------------------------------------------------------------------
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ----------------------------------------------------------------------
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 * ----------------------------------------------------------------------
 */

/*
 * Includes Inango Systems Ltd’s changes/modifications dated: 2021.
 * Changed/modified portions - Copyright (c) 2021 , Inango Systems Ltd.
 */

#ifndef OPENVSWITCH_BRCOMPAT_NETLINK_H
#define OPENVSWITCH_BRCOMPAT_NETLINK_H 1

#define BRC_GENL_FAMILY_NAME "brcompat"
#define GET_PARAMETER 0
#define SET_PARAMETER 1

/* Attributes that can be attached to the datapath's netlink messages. */
enum {
    BRC_GENL_A_UNSPEC,

    /*
     * "K:" attributes appear in messages from the kernel to userspace.
     * "U:" attributes appear in messages from userspace to the kernel.
     */

    /* BRC_GENL_C_DP_ADD, BRC_GENL_C_DP_DEL. */
    BRC_GENL_A_DP_NAME,        /* K: Datapath name. */

    /* BRC_GENL_C_DP_ADD, BRC_GENL_C_DP_DEL,
       BRC_GENL_C_PORT_ADD, BRC_GENL_C_PORT_DEL. */
    BRC_GENL_A_PORT_NAME,    /* K: Interface name. */

    /* BRC_GENL_C_DP_RESULT. */
    BRC_GENL_A_ERR_CODE,    /* U: Positive error code. */

    /* BRC_GENL_C_QUERY_MC. */
    BRC_GENL_A_MC_GROUP,    /* K: Generic netlink multicast group. */

    /* BRC_GENL_C_FDB_QUERY. */
    BRC_GENL_A_FDB_COUNT,    /* K: Number of FDB entries to read. */
    BRC_GENL_A_FDB_SKIP,    /* K: Record offset into FDB to start reading. */

    /* BRC_GENL_C_DP_RESULT. */
    BRC_GENL_A_FDB_DATA,    /* U: FDB records. */
    BRC_GENL_A_IFINDEXES,   /* U: "int" ifindexes of bridges or ports. */
    BRC_GENL_A_ULONG_VAL,   /* K: "unsigned long" Use in order to send parametrs to user space. */
    BRC_GENL_A_GET_ULONG,   /* U: "ulong" value of bridges parameters. */
    BRC_GENL_A_GET_STRING,  /* U: "string" value of bridges parameters. */

    /* seamless-ovs { */
    BRC_GENL_A_MG_IFIDX,    /* */
    BRC_GENL_A_MG_ADDR_TYPE,
    BRC_GENL_A_MG_GADDR,    /* */
    BRC_GENL_A_MG_FILTER,   /* */
    BRC_GENL_A_MG_COMPAT,   /* */
    BRC_GENL_A_MG_NSRC,     /* Number of source list entries */
    BRC_GENL_A_MG_SADDR,

    BRC_GENL_A_MAC_ADDR,
    BRC_GENL_A_MTU,

    BRC_GENL_A_PAD,
    __BRC_GENL_A_MAX,
    BRC_GENL_A_MAX = __BRC_GENL_A_MAX - 1
};

/* Commands that can be executed on the datapath's netlink interface. */
enum brc_genl_command {
    BRC_GENL_C_UNSPEC,

    /*
     * "K:" messages are sent by the kernel to userspace.
     * "U:" messages are sent by userspace to the kernel.
     */
    BRC_GENL_C_DP_ADD,        /* K: Datapath created. */
    BRC_GENL_C_DP_DEL,        /* K: Datapath destroyed. */
    BRC_GENL_C_DP_RESULT,    /* U: Return code from ovs-brcompatd. */
    BRC_GENL_C_PORT_ADD,    /* K: Port added to datapath. */
    BRC_GENL_C_PORT_DEL,    /* K: Port removed from datapath. */
    BRC_GENL_C_QUERY_MC,    /* U: Get multicast group for brcompat. */
    BRC_GENL_C_FDB_QUERY,    /* K: Read records from forwarding database. */
    BRC_GENL_C_GET_BRIDGES, /* K: Get ifindexes of all bridges. */
    BRC_GENL_C_GET_PORTS,   /* K: Get ifindexes of all ports on a bridge. */
    BRC_GENL_C_SET_AGEING_TIME,   /* K: Set  the  bridge  ageing  time. */
    BRC_GENL_C_SET_BRIDGE_FORWARD_DELAY,   /* K: Set the bridge forward delay. */
    BRC_GENL_C_SET_BRIDGE_HELLO_TIME,   /* K: Set  the  bridge  the hello interval. */
    BRC_GENL_C_SET_BRIDGE_MAX_AGE,   /* K: Set  the  bridge  max  age. */
    BRC_GENL_C_SET_BRIDGE_PRIORITY,   /* K: The bridge’s relative priority value for determining the root bridge. */
    BRC_GENL_C_SET_BRIDGE_STP_STATE,   /* K: Set  the  bridge stp state. */
    BRC_GENL_C_GET_BRIDGE_PRIORITY,   /* K: Get the bridge’s relative priority value. */
    BRC_GENL_C_GET_BRIDGE_STP_STATE,   /* K: Get the bridge stp state. */
    BRC_GENL_C_GET_BRIDGE_HELLO_TIME,   /* K: Get  the  bridge  the hello interval. */
    BRC_GENL_C_GET_BRIDGE_FORWARD_DELAY,   /* K: Get  the time that is spent in the listening and learning state. */
    BRC_GENL_C_GET_AGEING_TIME, /* K: Get  the  bridge  ageing  time. */
    BRC_GENL_C_GET_BRIDGE_MAX_AGE, /* K: Get  the  bridge  max  age. */
    BRC_GENL_C_GET_BRIDGE_MULTICAST_SNOOPING, /* K: Get  the  bridge  multicast snooping enabled. */
    BRC_GENL_C_SET_BRIDGE_MULTICAST_SNOOPING, /* K: Set  the  bridge  multicast snooping enabled. */
    BRC_GENL_C_GET_BRIDGE_ROOT_ID, /* K: Get the bridge root id. */
    BRC_GENL_C_GET_PORT_STATE, /* K: Get the port root id. */
    BRC_GENL_C_GET_PORT_PORT_NO, /* K: Get the port number. */
    BRC_GENL_C_GET_PORT_PATH_COST, /* K: Get the port path cost. */
    BRC_GENL_C_SET_PORT_PATH_COST, /* K: Set the port path cost. */
    BRC_GENL_C_MG_ADD,    /* K: seamless-ovs */
    BRC_GENL_C_MG_DEL,    /* K: seamless-ovs */
    BRC_GENL_C_SET_MCSNOOP_ROUT_PORT, /* K: Set the port as router port. */
    BRC_GENL_C_SET_MC_SNOOPING_FLAG, /* K: Set the multicast snooping flag. */
    BRC_GENL_C_GET_BRIDGE_BY_PORT, /* K: Get bridge name by port. */
    BRC_GENL_C_GET_BRIDGE_EXISTS, /* K: Check that bridge exists. */
    BRC_GENL_C_SET_MAC_ADDR, /* K: Set MAC address. */
    BRC_GENL_C_SET_MTU, /* K: Set MTU. */
    BRC_GENL_C_SET_PORT_MC_SNOOPING_FLOOD_REPORTS, /* K: Set the port multicast snooping flood reports */
    BRC_GENL_C_SET_PORT_HAIRPIN_MODE,   /* K: Set hairpin mode for the port */

    __BRC_GENL_C_MAX,
    BRC_GENL_C_MAX = __BRC_GENL_C_MAX - 1
};
#endif /* openvswitch/brcompat-netlink.h */
