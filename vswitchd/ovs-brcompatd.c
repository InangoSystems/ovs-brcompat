/* Copyright (c) 2008, 2009, 2010, 2011, 2012 Nicira, Inc.
 *
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
 */

/*
 * Includes Inango Systems Ltd’s changes/modifications dated: 2021.
 * Changed/modified portions - Copyright (c) 2021 , Inango Systems Ltd.
 */

#include <config.h>

#include <asm/param.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <net/if.h>
#include <linux/genetlink.h>
#include <linux/rtnetlink.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

#include <command-line.h>
#include <coverage.h>
#include <daemon.h>
#include <dirs.h>
#include <openvswitch/dynamic-string.h>
#include <fatal-signal.h>
#include <openvswitch/json.h>
//#include <leak-checker.h>
#include <netdev.h>
#include <netlink.h>
#include <netlink-notifier.h>
#include <netlink-socket.h>
#include <openvswitch/ofpbuf.h>
#include <openvswitch/brcompat-netlink.h>
#include <packets.h>
#include <openvswitch/poll-loop.h>
#include <process.h>
#include <rtnetlink.h>
#include <signals.h>
#include <sset.h>
#include <svec.h>
#include <timeval.h>
#include <unixctl.h>
#include <util.h>
#include <openvswitch/vlog.h>

VLOG_DEFINE_THIS_MODULE(brcompatd);

#define ETH_ADDR_SCAN_COUNT 6
/* Bridge and port priorities that should be used by default. */
#define STP_DEFAULT_BRIDGE_PRIORITY 32768
/* Default time values. */
#define STP_DEFAULT_MAX_AGE    20
#define STP_DEFAULT_HELLO_TIME 2
#define STP_DEFAULT_FWD_DELAY  15
/* Default mac-aging-time is y 300 seconds (5 minutes)*/
#define DEFAULT_MAC_AGING_TIME 300
#define STP_PATH_COST   100

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

/* xxx Just hangs if datapath is rmmod/insmod.  Learn to reconnect? */

static void set_default_parameters(const char *br_name);
static void set_default_port_parameters(const char *port_name);
static void parse_options(int argc, char *argv[]);
static void usage(void) OVS_NO_RETURN;

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 60);

/* --appctl: Absolute path to ovs-appctl. */
static char *appctl_program;

/* --vsctl: Absolute path to ovs-vsctl. */
static char *vsctl_program;

/* Options that we should generally pass to ovs-vsctl. */
#define VSCTL_OPTIONS "--timeout=5", "-vconsole:warn"
#define MAC_ADDR_CONFIG "other-config:hwaddr=+" ETH_ADDR_FMT
#define MAC_ADDR_ASSIGNMENT_STRLEN (sizeof(MAC_ADDR_CONFIG) + ETH_ADDR_STRLEN + 1)
#define FORMAT_MAC_ADDRESS_ASSIGNMENT(mac_addr, assignment) {\
  snprintf(assignment, sizeof(assignment), MAC_ADDR_CONFIG, ETH_ADDR_BYTES_ARGS(mac_addr));  \
}


/* Netlink socket to bridge compatibility kernel module. */
static struct nl_sock *brc_sock;

/* The Generic Netlink family number used for bridge compatibility. */
static int brc_family;

#ifdef HAVE_GENL_MULTICAST_GROUP_WITH_ID
static const struct nl_policy brc_multicast_policy[] = {
    [BRC_GENL_A_MC_GROUP] = {.type = NL_A_U32 }
};
#endif

static char *
capture_vsctl_valist(const char *arg0, va_list args, int *exit_code)
{
    char *stdout_log, *stderr_log;
    enum vlog_level log_level;
    struct svec argv;
    int status;
    char *msg;

    /* Compose arguments. */
    svec_init(&argv);
    svec_add(&argv, arg0);
    for (;;) {
        const char *arg = va_arg(args, const char *);
        if (!arg) {
            break;
        }
        svec_add(&argv, arg);
    }
    svec_terminate(&argv);

    /* Run process. */
    if (process_run_capture(argv.names, &stdout_log, &stderr_log, SIZE_MAX,
                            &status)) {
        svec_destroy(&argv);
        return NULL;
    }

    /* Log results. */
    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        *exit_code = code;
        log_level = code == 0 ? VLL_DBG : code == 1 ? VLL_WARN : VLL_ERR;
    } else {
        *exit_code = status;
        log_level = VLL_ERR;
    }
    msg = process_status_msg(status);
    VLOG(log_level, "ovs-vsctl exited (%s)", msg);
    if (stdout_log && *stdout_log) {
        VLOG(log_level, "ovs-vsctl wrote to stdout:\n%s\n", stdout_log);
    }
    if (stderr_log && *stderr_log) {
        VLOG(log_level, "ovs-vsctl wrote to stderr:\n%s\n", stderr_log);
    }
    free(msg);

    svec_destroy(&argv);

    free(stderr_log);
    if (WIFEXITED(status) && !WEXITSTATUS(status)) {
        return stdout_log;
    } else {
        free(stdout_log);
        return NULL;
    }
}

static char * SENTINEL(0)
capture_vsctl(const char *arg0, ...)
{
    char *stdout_log;
    va_list args;
    int exit_code;

    va_start(args, arg0);
    stdout_log = capture_vsctl_valist(arg0, args, &exit_code);
    va_end(args);

    return stdout_log;
}

static char * SENTINEL(0)
capture_vsctl_with_exit_code(int *exit_code, const char *arg0, ...)
{
    char *stdout_log;
    va_list args;

    va_start(args, arg0);
    stdout_log = capture_vsctl_valist(arg0, args, exit_code);
    va_end(args);

    return stdout_log;
}

static bool SENTINEL(0)
run_vsctl(const char *arg0, ...)
{
    char *stdout_log;
    va_list args;
    bool ok;
    int exit_code;

    va_start(args, arg0);
    stdout_log = capture_vsctl_valist(arg0, args, &exit_code);
    va_end(args);

    ok = stdout_log != NULL;
    free(stdout_log);
    return ok;
}
#ifdef HAVE_GENL_MULTICAST_GROUP_WITH_ID
static int
lookup_brc_multicast_group(int *multicast_group)
{
    struct nl_sock *sock;
    struct ofpbuf request, *reply;
    struct nlattr *attrs[ARRAY_SIZE(brc_multicast_policy)];
    int retval;

    retval = nl_sock_create(NETLINK_GENERIC, &sock);
    if (retval) {
        return retval;
    }
    ofpbuf_init(&request, 0);
    nl_msg_put_genlmsghdr(&request, 0, brc_family,
            NLM_F_REQUEST, BRC_GENL_C_QUERY_MC, 1);
    retval = nl_sock_transact(sock, &request, &reply);
    ofpbuf_uninit(&request);
    if (retval) {
        nl_sock_destroy(sock);
        return retval;
    }
    if (!nl_policy_parse(reply, NLMSG_HDRLEN + GENL_HDRLEN,
                         brc_multicast_policy, attrs,
                         ARRAY_SIZE(brc_multicast_policy))) {
        nl_sock_destroy(sock);
        ofpbuf_delete(reply);
        return EPROTO;
    }
    *multicast_group = nl_attr_get_u32(attrs[BRC_GENL_A_MC_GROUP]);
    nl_sock_destroy(sock);
    ofpbuf_delete(reply);

    return 0;
}
#endif
/* Opens a socket for brcompat notifications.  Returns 0 if successful,
 * otherwise a positive errno value. */
static int
brc_open(struct nl_sock **sock)
{
    unsigned int multicast_group = 0;
    int retval;

    retval = nl_lookup_genl_family(BRC_GENL_FAMILY_NAME, &brc_family);
    if (retval) {
        return retval;
    }
#ifdef HAVE_GENL_MULTICAST_GROUP_WITH_ID
    retval = lookup_brc_multicast_group(&multicast_group);
#else
    retval = nl_lookup_genl_mcgroup(BRC_GENL_FAMILY_NAME, BRC_GENL_FAMILY_NAME, &multicast_group);
#endif
    if (retval) {
        return retval;
    }

    retval = nl_sock_create(NETLINK_GENERIC, sock);
    if (retval) {
        return retval;
    }

    retval = nl_sock_join_mcgroup(*sock, multicast_group);
    if (retval) {
        nl_sock_destroy(*sock);
        *sock = NULL;
    }
    return retval;
}

static int
parse_command(struct ofpbuf *buffer, uint32_t *seq, const char **br_name,
              const char **port_name, uint64_t *count, uint64_t *skip, uint64_t *ulong_param, const char **mac_addr)
{
    static const struct nl_policy policy[] = {
        [BRC_GENL_A_DP_NAME] = { .type = NL_A_STRING, .optional = true },
        [BRC_GENL_A_PORT_NAME] = { .type = NL_A_STRING, .optional = true },
        [BRC_GENL_A_FDB_COUNT] = { .type = NL_A_U64, .optional = true },
        [BRC_GENL_A_FDB_SKIP] = { .type = NL_A_U64, .optional = true },
        [BRC_GENL_A_ULONG_VAL] = { .type = NL_A_U64, .optional = true },
        [BRC_GENL_A_MAC_ADDR] = { .type = NL_A_UNSPEC, .optional = true },
    };
    struct nlattr *attrs[ARRAY_SIZE(policy)];

    if (!nl_policy_parse(buffer, NLMSG_HDRLEN + GENL_HDRLEN, policy,
                         attrs, ARRAY_SIZE(policy))
        || (br_name && !attrs[BRC_GENL_A_DP_NAME])
        || (port_name && !attrs[BRC_GENL_A_PORT_NAME])
        || (count && !attrs[BRC_GENL_A_FDB_COUNT])
        || (skip && !attrs[BRC_GENL_A_FDB_SKIP])
        || (ulong_param && !attrs[BRC_GENL_A_ULONG_VAL])) {
        return EINVAL;
    }

    *seq = ((struct nlmsghdr *) buffer->data)->nlmsg_seq;
    if (br_name) {
        *br_name = nl_attr_get_string(attrs[BRC_GENL_A_DP_NAME]);
    }
    if (port_name) {
        *port_name = nl_attr_get_string(attrs[BRC_GENL_A_PORT_NAME]);
    }
    if (count) {
        *count = nl_attr_get_u64(attrs[BRC_GENL_A_FDB_COUNT]);
    }
    if (skip) {
        *skip = nl_attr_get_u64(attrs[BRC_GENL_A_FDB_SKIP]);
    }
    if (ulong_param) {
        *ulong_param = nl_attr_get_u64(attrs[BRC_GENL_A_ULONG_VAL]);
    }
    if (mac_addr && attrs[BRC_GENL_A_MAC_ADDR]) {
        *mac_addr = nl_attr_get_unspec(attrs[BRC_GENL_A_MAC_ADDR], ETH_ALEN);
    }
    return 0;
}

/* seamless-ovs { */
static char *
ipaddrs_to_string(ipaddr_t *addrs, uint32_t naddrs)
{
    if (!naddrs)
        return NULL;

    const uint32_t size = 2 * (addrs->type == IPV4 ? sizeof(addrs->addr.ip4) : sizeof(addrs->addr.ip6));
    char *addrs_str = malloc(naddrs*(size + 1) + 1);
    char *s = addrs_str;
    int count;
    for (uint32_t i = 0; i < naddrs; ++i) {
        if (addrs[i].type == IPV4)
        {
            count = sprintf(s, "%08x,", addrs[i].addr.ip4.s_addr);
            if (count <= 0) {
                free(addrs_str);
                return NULL;
            }
            s += count;
        }
        else
        {
            for (uint32_t j = 0; j < 4; ++j) {
                count = sprintf(s, (j < 3 ? "%08x" : "%08x,"), addrs[i].addr.ip6.s6_addr32[j]);
                if (count <= 0) {
                    free(addrs_str);
                    return NULL;
                }
                s += count;
            }
        }
    }

    *(s - 1) = '\0';

    return addrs_str;
}

static int
parse_command_mg(struct ofpbuf *buffer, uint32_t *seq, const char **br_name,
                 const char **port_name, ipaddr_t **gaddr, uint32_t *filter, uint32_t *compat, 
                 uint32_t *nsrc, ipaddr_t **saddrs)
{
    static const struct nl_policy policy[] = {
        [BRC_GENL_A_DP_NAME]      = { .type = NL_A_STRING, .optional = true },
        [BRC_GENL_A_PORT_NAME]    = { .type = NL_A_STRING, .optional = true },
        [BRC_GENL_A_MG_GADDR]     = { .type = NL_A_UNSPEC, .optional = true },
        [BRC_GENL_A_MG_FILTER]    = { .type = NL_A_U32,    .optional = true },
        [BRC_GENL_A_MG_COMPAT]    = { .type = NL_A_U32,    .optional = true },
        [BRC_GENL_A_MG_NSRC]      = { .type = NL_A_U32,    .optional = true },
        [BRC_GENL_A_MG_SADDR]     = { .type = NL_A_UNSPEC, .optional = true },
    };
    struct nlattr  *attrs[ARRAY_SIZE(policy)];

    VLOG_DBG("parse_command_mg()");

    if (!nl_policy_parse(buffer, NLMSG_HDRLEN + GENL_HDRLEN, policy, attrs, ARRAY_SIZE(policy))
        || (br_name   && !attrs[BRC_GENL_A_DP_NAME])
        || (port_name && !attrs[BRC_GENL_A_PORT_NAME])
        || (gaddr     && !attrs[BRC_GENL_A_MG_GADDR])
        || (filter    && !attrs[BRC_GENL_A_MG_FILTER])
        || (compat    && !attrs[BRC_GENL_A_MG_COMPAT])
        || (nsrc      && !attrs[BRC_GENL_A_MG_NSRC])
    ) 
    {
        VLOG_ERR("parse_command_mg: nl_policy_parse() failed or some attributes are missing");
        return EINVAL;
    }

    *seq = ((struct nlmsghdr *) buffer->data)->nlmsg_seq;
    VLOG_DBG("parse_command_mg: got seq");

    if (br_name) {
        *br_name = nl_attr_get_string(attrs[BRC_GENL_A_DP_NAME]);
        VLOG_DBG("parse_command_mg: got br_name");
    }

    if (port_name) {
        *port_name = nl_attr_get_string(attrs[BRC_GENL_A_PORT_NAME]);
        VLOG_DBG("parse_command_mg: got port");
    }

    if (gaddr) {
        *gaddr = (ipaddr_t *)nl_attr_get_unspec(attrs[BRC_GENL_A_MG_GADDR], sizeof(ipaddr_t));
        VLOG_DBG("parse_command_mg: got gaddr");
    }

    if (filter) {
        *filter = nl_attr_get_u32(attrs[BRC_GENL_A_MG_FILTER]);
        VLOG_DBG("parse_command_mg: got filter");
    }

    if (compat) {
        *compat = nl_attr_get_u32(attrs[BRC_GENL_A_MG_COMPAT]);
        VLOG_DBG("parse_command_mg: got compat");
    }

    if (nsrc) {
        *nsrc = nl_attr_get_u32(attrs[BRC_GENL_A_MG_NSRC]);
        VLOG_DBG("parse_command_mg: got nsrc = %u", *nsrc);

        if (saddrs && *nsrc && attrs[BRC_GENL_A_MG_SADDR]) {
            *saddrs = (ipaddr_t *)nl_attr_get_unspec(attrs[BRC_GENL_A_MG_SADDR], *nsrc * sizeof(ipaddr_t));
            VLOG_DBG("parse_command_mg: got saddrs");
        }
    }

    return 0;
}

/* } seamless-ovs */

/* Composes and returns a reply to a request made by the datapath with error
 * code 'error'.  The caller may add additional attributes to the message, then
 * it may send it with send_reply(). */
static struct ofpbuf *
compose_reply(int error)
{
    struct ofpbuf *reply = ofpbuf_new(4096);
    nl_msg_put_genlmsghdr(reply, 32, brc_family, NLM_F_REQUEST,
                          BRC_GENL_C_DP_RESULT, 1);
    nl_msg_put_u32(reply, BRC_GENL_A_ERR_CODE, error);
    return reply;
}

/* Sends 'reply' to the datapath, using sequence number 'nlmsg_seq', and frees
 * it. */
static void
send_reply(struct ofpbuf *reply, uint32_t nlmsg_seq)
{
    int retval = nl_sock_send_seq(brc_sock, reply, nlmsg_seq, false);
    if (retval) {
        VLOG_WARN_RL(&rl, "replying to brcompat request: %s",
                     ovs_strerror(retval));
    }
    ofpbuf_delete(reply);
}

/* Composes and sends a reply to a request made by the datapath with Netlink
 * sequence number 'seq' and error code 'error'. */
static void
send_simple_reply(uint32_t seq, int error)
{
    send_reply(compose_reply(error), seq);
}

/* Start and stop for rsc-server and rsc-proxy for specified bridge */
static int
on_bridge_add_del(bool add, const char *br_name)
{
    int error;
    const char *add_br = add ? "true" : "false";
    const char *path_on_ovs_bridge_event_script = "/etc/scripts/on_ovs_bridge_event.sh";

    if (access(path_on_ovs_bridge_event_script, F_OK) == 0 ) {
        if (!run_vsctl(path_on_ovs_bridge_event_script, add_br, br_name, (char *) NULL)) {
            error = EINVAL;
        }
    } else {
        error = ENOENT;
    }
    return error;
}

static int
handle_bridge_cmd(struct ofpbuf *buffer, bool add)
{
    const char *br_name;
    const unsigned char *mac_addr = NULL;
    uint32_t seq;
    int error;
    int vsctl_ok;

    error = parse_command(buffer, &seq, &br_name, NULL, NULL, NULL, NULL, (const char **)&mac_addr);
    if (!error) {
        const char *vsctl_cmd = add ? "add-br" : "del-br";
        const char *brctl_cmd = add ? "addbr" : "delbr";

        if (mac_addr) {
            char assignment[MAC_ADDR_ASSIGNMENT_STRLEN];
            FORMAT_MAC_ADDRESS_ASSIGNMENT(mac_addr, assignment);

            vsctl_ok = run_vsctl(vsctl_program, VSCTL_OPTIONS,
                        "--", vsctl_cmd, br_name,
                        "--", "set", "bridge", br_name, assignment,
                        "--", "comment", "ovs-brcompatd:", brctl_cmd, br_name,
                        (char *) NULL);
        } else {
            vsctl_ok = run_vsctl(vsctl_program, VSCTL_OPTIONS,
                        "--", vsctl_cmd, br_name,
                        "--", "comment", "ovs-brcompatd:", brctl_cmd, br_name,
                        (char *) NULL);
        }
        if (!vsctl_ok) {
            error = add ? EEXIST : ENXIO;
        } else {
            if(!on_bridge_add_del(add, br_name)) {
                VLOG_WARN_RL(&rl, "Function on_bridge_add_del failed to start/stop rsc-server and rsc-proxy for specified bridge");
            }
        }
        if (add && !error)
            set_default_parameters(br_name);
        send_simple_reply(seq, error);
    }
    return error;
}

static int
handle_port_cmd(struct ofpbuf *buffer, bool add)
{
    const char *br_name, *port_name;
    uint32_t seq;
    int error;
    int vsctl_ok;

    error = parse_command(buffer, &seq, &br_name, &port_name, NULL, NULL, NULL, NULL);
    if (!error) {
        const char *vsctl_cmd = add ? "add-port" : "del-port";
        const char *brctl_cmd = add ? "addif" : "delif";
        vsctl_ok = run_vsctl(vsctl_program, VSCTL_OPTIONS,
                       "--", vsctl_cmd, br_name, port_name,
                       "--", "comment", "ovs-brcompatd:", brctl_cmd,
                       br_name, port_name, (char *) NULL);
        if (!vsctl_ok) {
            error = EINVAL;
        }
        if (add && !error)
            set_default_port_parameters(port_name);
        send_simple_reply(seq, error);
    }
    return error;
}

/* seamless-ovs { */
static int
handle_mg_add_del_cmd(struct ofpbuf *buffer, bool add)
{
    const char *appctl_cmd = add ? "mdb/add-grp" : "mdb/del-grp";
    const char *br_name;
    const char *port_name;
    uint32_t    seq;
    ipaddr_t   *gaddr;
    uint32_t    filter;
    uint32_t    compat;
    uint32_t    nsrc = 0;
    ipaddr_t   *saddrs;
    char       *args[5];
    int         error;

    VLOG_DBG("handle_mg_add_del_cmd(add=%d)", add);

    if (add) {
        error = parse_command_mg(buffer, &seq, &br_name, &port_name, &gaddr, &filter, &compat, &nsrc, &saddrs);
    }
    else {
        error = parse_command_mg(buffer, &seq, &br_name, &port_name, &gaddr, NULL, NULL, NULL, NULL);  
    }

    if (error) {
        VLOG_INFO("handle_mg_add_del_cmd(add=%d): parse error -> %d", add, error);
    }
    else {
        args[0] = NULL;
        args[1] = ipaddrs_to_string(gaddr, 1);
        if (add) {
            args[2] = xasprintf("%u", filter);
            args[3] = xasprintf("%u", compat);
            args[4] = ipaddrs_to_string(saddrs, nsrc);
        }
        else {
            args[2] = NULL;
            args[3] = NULL;
            args[4] = NULL;
        }

        if (!run_vsctl(appctl_program, "--", appctl_cmd, br_name, port_name,
                       args[1], args[2], args[3], args[4],
                       (char *) NULL)
           )
        {
            error = EINVAL;
        }

        VLOG_INFO("handle_mg_add_del_cmd: %s %s %s %s %s %s %s -> %d", appctl_cmd, br_name, port_name, args[1], args[2], args[3], args[4] ? args[4] : "", error);

        for (int i = 4; i > 0; --i) {
            free(args[i]);
        }
    }

    send_simple_reply(seq, error);

    return error;
}
/* } seamless-ovs */

static char *
linux_bridge_to_ovs_bridge(const char *linux_name, int *br_vlanp)
{
    char *save_ptr = NULL;
    const char *br_name, *br_vlan;
    char *br_name_copy;
    char *output;

    output = capture_vsctl(vsctl_program, VSCTL_OPTIONS,
                           "--", "br-to-parent", linux_name,
                           "--", "br-to-vlan", linux_name,
                           (char *) NULL);
    if (!output) {
        return NULL;
    }

    br_name = strtok_r(output, " \t\r\n", &save_ptr);
    br_vlan = strtok_r(NULL, " \t\r\n", &save_ptr);
    if (!br_name || !br_vlan) {
        free(output);
        return NULL;
    }
    br_name_copy = xstrdup(br_name);
    *br_vlanp = atoi(br_vlan);

    free(output);

    return br_name_copy;
}

static void
get_bridge_ifaces(const char *br_name, struct sset *ifaces)
{
    char *save_ptr = NULL;
    char *output;
    char *iface;

    output = capture_vsctl(vsctl_program, VSCTL_OPTIONS, "list-ifaces",
                           br_name, (char *) NULL);
    if (!output) {
        return;
    }

    for (iface = strtok_r(output, " \t\r\n", &save_ptr); iface;
         iface = strtok_r(NULL, " \t\r\n", &save_ptr)) {
        sset_add(ifaces, iface);
    }
    free(output);
}

static int
handle_fdb_query_cmd(struct ofpbuf *buffer)
{
    /* This structure is copied directly from the Linux 2.6.30 header files.
     * It would be more straightforward to #include <linux/if_bridge.h>, but
     * the 'port_hi' member was only introduced in Linux 2.6.26 and so systems
     * with old header files won't have it. */
    struct __fdb_entry {
        __u8 mac_addr[6];
        __u8 port_no;
        __u8 is_local;
        __u32 ageing_timer_value;
        __u8 port_hi;
        __u8 pad0;
        __u16 unused;
    };

    struct eth_addr *local_macs;
    int n_local_macs;
    int i;

    /* Impedance matching between the vswitchd and Linux kernel notions of what
     * a bridge is.  The kernel only handles a single VLAN per bridge, but
     * vswitchd can deal with all the VLANs on a single bridge.  We have to
     * pretend that the former is the case even though the latter is the
     * implementation. */
    const char *linux_name;   /* Name used by brctl. */
    int br_vlan;                /* VLAN tag. */
    struct sset ifaces;

    struct ofpbuf query_data;
    const char *iface_name;
    struct ofpbuf *reply;
    uint64_t count, skip;
    char *br_name;
    char *output;
    char *save_ptr;
    uint32_t seq;
    int error;

    /* Parse the command received from brcompat. */
    error = parse_command(buffer, &seq, &linux_name, NULL, &count, &skip, NULL, NULL);
    if (error) {
        return error;
    }

    /* Figure out vswitchd bridge and VLAN. */
    br_name = linux_bridge_to_ovs_bridge(linux_name, &br_vlan);
    if (!br_name) {
        error = EINVAL;
        send_simple_reply(seq, error);
        return error;
    }

    /* Fetch the forwarding database using ovs-appctl. */
    output = capture_vsctl(appctl_program, "fdb/show", br_name, (char *) NULL);
    free(br_name);

    if (!output) {
        error = ECHILD;
        send_simple_reply(seq, error);
        return error;
    }

    /* Fetch the MAC address for each interface on the bridge, so that we can
     * fill in the is_local field in the response. */
    sset_init(&ifaces);
    get_bridge_ifaces(linux_name, &ifaces);
    local_macs = xmalloc(sset_count(&ifaces) * sizeof *local_macs);
    n_local_macs = 0;
    SSET_FOR_EACH (iface_name, &ifaces) {
        struct eth_addr *mac = &local_macs[n_local_macs];
        struct netdev *netdev;

        error = netdev_open(iface_name, "system", &netdev);
        if (!error) {
            if (!netdev_get_etheraddr(netdev, mac)) {
                n_local_macs++;
            }
            netdev_close(netdev);
        }
    }
    sset_destroy(&ifaces);

    /* Parse the response from ovs-appctl and convert it to binary format to
     * pass back to the kernel. */
    ofpbuf_init(&query_data, sizeof(struct __fdb_entry) * 8);
    save_ptr = NULL;
    strtok_r(output, "\n", &save_ptr); /* Skip header line. */
    while (count > 0) {
        struct __fdb_entry *entry;
        int port = 0, vlan, age;
        char port_str[16] = {0};
        struct eth_addr mac;
        char *line;
        bool is_local;

        line = strtok_r(NULL, "\n", &save_ptr);
        if (!line) {
            break;
        }

        while (line[0] && isspace(line[0]))
            ++line;

        if (sscanf(line, "%s %d "ETH_ADDR_SCAN_FMT" %d",
                   port_str, &vlan, ETH_ADDR_SCAN_ARGS(mac), &age)
            != 2 + ETH_ADDR_SCAN_COUNT + 1) {
            static struct vlog_rate_limit rl_l = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_INFO_RL(&rl_l, "fdb/show output has invalid format: %s", line);
            continue;
        }

        if (strcmp(port_str, "LOCAL") && sscanf(port_str, "%d", &port) != 1) {
            static struct vlog_rate_limit rl_l = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_INFO_RL(&rl_l, "fdb/show port has invalid format: %s", line);
            continue;
        }

        if (vlan != br_vlan) {
            continue;
        }

        if (skip > 0) {
            skip--;
            continue;
        }

        /* Is this the MAC address of an interface on the bridge? */
        is_local = false;
        for (i = 0; i < n_local_macs; i++) {
            if (eth_addr_equals(local_macs[i], mac)) {
                is_local = true;
                break;
            }
        }

        entry = ofpbuf_put_uninit(&query_data, sizeof *entry);
        memcpy(entry->mac_addr, mac.ea, ETH_ADDR_LEN);
        entry->port_no = port & 0xff;
        entry->is_local = is_local;
        entry->ageing_timer_value = age * HZ;
        entry->port_hi = (port & 0xff00) >> 8;
        entry->pad0 = 0;
        entry->unused = 0;
        count--;
    }
    free(output);

    /* Compose and send reply to datapath. */
    reply = compose_reply(0);
    nl_msg_put_unspec(reply, BRC_GENL_A_FDB_DATA,
                      query_data.data, query_data.size);
    send_reply(reply, seq);

    /* Free memory. */
    ofpbuf_uninit(&query_data);
    free(local_macs);

    return 0;
}

static void
send_ifindex_reply(uint32_t seq, char *output)
{
    size_t allocated_indices;
    char *save_ptr = NULL;
    struct ofpbuf *reply;
    const char *iface;
    size_t n_indices;
    int *indices;

    indices = NULL;
    n_indices = allocated_indices = 0;
    for (iface = strtok_r(output, " \t\r\n", &save_ptr); iface;
         iface = strtok_r(NULL, " \t\r\n", &save_ptr)) {
        int ifindex;

        if (n_indices >= allocated_indices) {
            indices = x2nrealloc(indices, &allocated_indices, sizeof *indices);
        }

        ifindex = if_nametoindex(iface);
        if (ifindex) {
            indices[n_indices++] = ifindex;
        }
    }

    /* Compose and send reply. */
    reply = compose_reply(0);
    nl_msg_put_unspec(reply, BRC_GENL_A_IFINDEXES,
                      indices, n_indices * sizeof *indices);
    send_reply(reply, seq);

    /* Free memory. */
    free(indices);
}

static int
handle_get_bridges_cmd(struct ofpbuf *buffer)
{
    char *output;
    uint32_t seq;
    int error;

    /* Parse Netlink command.
     *
     * The command doesn't actually have any arguments, but we need the
     * sequence number to send the reply. */
    error = parse_command(buffer, &seq, NULL, NULL, NULL, NULL, NULL, NULL);
    if (error) {
        return error;
    }

    output = capture_vsctl(vsctl_program, VSCTL_OPTIONS, "list-br", (char *) NULL);
    if (!output) {
        return ENODEV;
    }

    send_ifindex_reply(seq, output);
    free(output);
    return 0;
}

static int
handle_get_ports_cmd(struct ofpbuf *buffer)
{
    const char *linux_name;
    uint32_t seq;
    char *output;
    int error;

    /* Parse Netlink command. */
    error = parse_command(buffer, &seq, &linux_name, NULL, NULL, NULL, NULL, NULL);
    if (error) {
        return error;
    }

    output = capture_vsctl(vsctl_program, VSCTL_OPTIONS, "list-ports", linux_name,
                           (char *) NULL);
    if (!output) {
        return ENODEV;
    }

    send_ifindex_reply(seq, output);
    free(output);
    return 0;
}

static int
handle_get_string_value(struct ofpbuf *buffer, const char *sub_cmd)
{
    const char *br_name;
    uint32_t seq;
    char *output, *result;
    int error, size;
    struct ofpbuf *reply;

    /* Parse Netlink command.
     *
     * The command doesn't actually have any arguments, but we need the
     * sequence number to send the reply. */
    /* Parse Netlink command. */
    error = parse_command(buffer, &seq, &br_name, NULL, NULL, NULL, NULL, NULL);
    if (error) {
        return error;
    }

    output = capture_vsctl(vsctl_program, VSCTL_OPTIONS, "get", "Bridge", br_name, sub_cmd,
                           (char *) NULL);
    if (!output) {
            VLOG_ERR("handle_get_string_value get output error!\n");
            result = "";
            size = strlen(result);
            error = EINVAL;
    } else {
        result = output;
        result++;
        size = (strchr(result, '\"') - result);
    }

    /* Compose and send reply. */
    reply = compose_reply(0);
    nl_msg_put_unspec(reply, BRC_GENL_A_GET_STRING,
                      result, size * sizeof *result);
    send_reply(reply, seq);

    free(output);
    return 0;
}

static int
handle_get_bridge_name_value(struct ofpbuf *buffer)
{
    const char *port_name;
    uint32_t seq;
    char *output, *result;
    int error, size;
    struct ofpbuf *reply;

    /* Parse Netlink command.
     *
     * The command doesn't actually have any arguments, but we need the
     * sequence number to send the reply. */
    /* Parse Netlink command. */
    error = parse_command(buffer, &seq, &port_name, NULL, NULL, NULL, NULL, NULL);
    if (error) {
        return error;
    }
    output = capture_vsctl(vsctl_program, VSCTL_OPTIONS, "port-to-br", port_name,
                           (char *) NULL);
    if (!output) {
        VLOG_ERR("handle_get_bridge_name_value get output error!\n");
        result = "";
        size = strlen(result);
        error = EINVAL;
    } else {
        result = output;
        size = (strchr(result, '\n') - result);
    }

    /* Compose and send reply. */
    reply = compose_reply(0);
    nl_msg_put_unspec(reply, BRC_GENL_A_GET_STRING,
                      result, size * sizeof(*result));
    send_reply(reply, seq);

    free(output);
    return 0;
}

static int
handle_get_bridge_exists(struct ofpbuf *buffer)
{
    const char *br_name;
    uint32_t seq;
    int error;
    struct ofpbuf *reply;
    int exit_code = 1;

    /* Parse Netlink command.
     *
     * The command doesn't actually have any arguments, but we need the
     * sequence number to send the reply. */
    /* Parse Netlink command. */
    error = parse_command(buffer, &seq, &br_name, NULL, NULL, NULL, NULL, NULL);
    if (error) {
        return error;
    }
    capture_vsctl_with_exit_code(&exit_code, vsctl_program, VSCTL_OPTIONS, "br-exists", br_name,
                           (char *) NULL);

    /* Compose and send reply. */
    reply = compose_reply(0);
    nl_msg_put_u32(reply, BRC_GENL_A_GET_ULONG, exit_code);
    send_reply(reply, seq);

    return 0;
}

static int
handle_set_ulong_val_cmd(struct ofpbuf *buffer, const char *sub_cmd)
{
    const char *br_name;
    char *str_other_config;
    char *str_param;
    uint64_t param;
    uint32_t seq;
    int error;

    error = parse_command(buffer, &seq, &br_name, NULL, NULL, NULL, &param, NULL);

    if (!error) {
        str_other_config = xasprintf("other_config:%s=%"PRIu64, sub_cmd, param);
        str_param        = xasprintf("%"PRIu64, param);

        if (!run_vsctl(vsctl_program, VSCTL_OPTIONS,
                       "--", "set", "Bridge", br_name, str_other_config,
                       "--", "comment", "ovs-brcompatd:", sub_cmd,
                       br_name, str_param, (char *) NULL)) {
            error = EINVAL;
        }
        send_simple_reply(seq, error);

        free(str_other_config);
        free(str_param);
    }
    return error;
}

static int
handle_set_ulong_val_port_cmd(struct ofpbuf *buffer, const char *sub_cmd)
{
    const char *pr_name;
    char *str_other_config;
    char *str_param;
    uint64_t param;
    uint32_t seq;
    int error;

    error = parse_command(buffer, &seq, &pr_name, NULL, NULL, NULL, &param, NULL);

    if (!error) {
        str_other_config = xasprintf("other_config:%s=%"PRIu64, sub_cmd, param);
        str_param        = xasprintf("%"PRIu64, param);

        if (!run_vsctl(vsctl_program, VSCTL_OPTIONS,
                       "--", "set", "Port", pr_name, str_other_config,
                       "--", "comment", "ovs-brcompatd:", sub_cmd,
                       pr_name, str_param, (char *) NULL)) {
            error = EINVAL;
        }
        send_simple_reply(seq, error);

        free(str_other_config);
        free(str_param);
    }
    return error;
}

static int
handle_set_ulong_val_interface_cmd(struct ofpbuf *buffer, const char *sub_cmd)
{
    const char *pr_name;
    char *str_key_value;
    char *str_param;
    uint64_t param;
    uint32_t seq;
    int error;

    error = parse_command(buffer, &seq, &pr_name, NULL, NULL, NULL, &param, NULL);

    if (!error) {
        str_key_value = xasprintf("%s=%"PRIu64, sub_cmd, param);
        str_param     = xasprintf("%"PRIu64, param);

        if (!run_vsctl(vsctl_program, VSCTL_OPTIONS,
                       "--", "set", "Interface", pr_name, str_key_value,
                       "--", "comment", "ovs-brcompatd:", sub_cmd,
                       pr_name, str_param, (char *) NULL)) {
            error = EINVAL;
        }
        send_simple_reply(seq, error);

        free(str_key_value);
        free(str_param);
    }
    return error;
}

static int
handle_set_boolean_val_cmd(struct ofpbuf *buffer, const char *sub_cmd)
{
    const char *br_name;
    char *str_key_value;
    uint64_t param;
    uint32_t seq;
    int error;

    error = parse_command(buffer, &seq, &br_name, NULL, NULL, NULL, &param, NULL);

    if (!error) {
        str_key_value = xasprintf("%s=%s", sub_cmd, param ? "true" : "false");

        if (!run_vsctl(vsctl_program, VSCTL_OPTIONS,
                       "--", "set", "Bridge", br_name, str_key_value,
                       "--", "comment", "ovs-brcompatd:", sub_cmd,
                       br_name, param ? "true" : "false", (char *) NULL)) {
            error = EINVAL;
        }
        send_simple_reply(seq, error);

        free(str_key_value);
    }
    return error;
}

static int
handle_set_boolean_val_port_cmd(struct ofpbuf *buffer, const char *sub_cmd)
{
    const char *pr_name;
    char *str_key_value;
    uint64_t param;
    uint32_t seq;
    int error;

    error = parse_command(buffer, &seq, &pr_name, NULL, NULL, NULL, &param, NULL);

    if (!error) {
        str_key_value = xasprintf("%s=%s", sub_cmd, param ? "true" : "false");

        if (!run_vsctl(vsctl_program, VSCTL_OPTIONS,
                       "--", "set", "Port", pr_name, str_key_value,
                       "--", "comment", "ovs-brcompatd:", sub_cmd,
                       pr_name, param ? "true" : "false", (char *) NULL)) {
            error = EINVAL;
        }
        send_simple_reply(seq, error);

        free(str_key_value);
    }
    return error;
}

static int
handle_set_mc_router_port_cmd(struct ofpbuf *buffer)
{
    const char *br_name, *p_name;
    char *str_key_value_type, *str_key_value_expires;
    uint64_t ip_type, expires;
    uint32_t seq;
    int error;

    error = parse_command(buffer, &seq, &br_name, &p_name, &expires, NULL, &ip_type, NULL);

    if (!error) {
        str_key_value_type = xasprintf("%"PRIu64, ip_type);
        str_key_value_expires = xasprintf("%"PRIu64, expires);

        if (!run_vsctl(appctl_program,
                       "--", "mdb/set-mrouter-port", br_name, p_name, str_key_value_type,
                        str_key_value_expires, (char *) NULL)) {
            error = EINVAL;
        }
        send_simple_reply(seq, error);

        free(str_key_value_type);
        free(str_key_value_expires);
    }
    return error;
}

static int
handle_set_mac_addr_cmd(struct ofpbuf *buffer)
{
    const char *br_name;
    const unsigned char *mac = NULL;
    uint32_t    seq = 0;
    int         error;

    VLOG_DBG("handle_set_mac_addr_cmd()");

    error = parse_command(buffer, &seq, &br_name, NULL, NULL, NULL, NULL, (const char **)&mac);
    if (!mac) {
        error = EINVAL;
    }

    if (error) {
        VLOG_ERR("handle_set_mac_addr_cmd(): failed to parse the command: parse_command_mac_addr() -> %d", error);
    }
    else {
        char assignment[MAC_ADDR_ASSIGNMENT_STRLEN];
        FORMAT_MAC_ADDRESS_ASSIGNMENT(mac, assignment);

        VLOG_DBG("handle_set_mac_addr_cmd(): %s -- set bridge %s %s\n", vsctl_program, br_name, assignment);
        if (!run_vsctl(vsctl_program, "--no-wait", "--", "set", "bridge", br_name, assignment, (char *) NULL)) {
            error = EINVAL;
        }
    }

    send_simple_reply(seq, error);
    VLOG_DBG("handle_set_mac_addr_cmd() -> %d\n", error);

    return error;
}

static int
handle_get_ulong_val_cmd(struct ofpbuf *buffer, const char *sub_cmd)
{
    const char *br_name;
    uint32_t seq;
    char *output, *end_p = NULL;
    int error;
    unsigned long result;
    struct ofpbuf *reply;

    /* Parse Netlink command. */
    error = parse_command(buffer, &seq, &br_name, NULL, NULL, NULL, NULL, NULL);
    if (error) {
        return error;
    }

    output = capture_vsctl(vsctl_program, VSCTL_OPTIONS, "get", "Bridge", br_name, sub_cmd, (char *) NULL);

    if (!output) {
        result = 0;
        goto send_reply;
    }

    if (strcmp(output, "true\n") == 0) {
        result = 1;
    } else if (strcmp(output, "false\n") == 0) {
        result = 0;
    } else {
        if (*output != '\"') {
            VLOG_ERR("%s\n", output);
            result = 0;
            goto send_reply;
        }

        errno = 0;
        result = strtoul(output + 1, &end_p, 10);
        if (end_p == (output + 1) || *end_p != '\"' || (result == ULONG_MAX && (errno == ERANGE))) {
            VLOG_ERR("Error occurred during converting string to int cmd\n");
            result = 0;
            goto send_reply;
        }
    }

send_reply:
    /* Compose and send reply. */
    reply = compose_reply(0);
    nl_msg_put_u32(reply, BRC_GENL_A_GET_ULONG, result);
    send_reply(reply, seq);

    free(output);
    return 0;
}

static int
handle_get_ulong_val_port_cmd(struct ofpbuf *buffer, const char *sub_cmd)
{
    const char *br_name;
    uint32_t seq;
    char *output, *end_p = NULL;
    int error;
    unsigned long result;
    struct ofpbuf *reply;

    /* Parse Netlink command. */
    error = parse_command(buffer, &seq, &br_name, NULL, NULL, NULL, NULL, NULL);
    if (error) {
        return error;
    }

    output = capture_vsctl(vsctl_program, VSCTL_OPTIONS, "get", "Port", br_name, sub_cmd, (char *) NULL);
 
    if (!output) {
        VLOG_ERR("handle_get_ulong_val_port_cmd has no output\n");
        result = 0;
        goto send_reply;
    }

    if (strcmp(output, "true\n") == 0) {
        result = 1;
    } else if (strcmp(output, "false\n") == 0) {
        result = 0;
    } else if (strcmp(output, "blocking\n") == 0) {
        result = 0;
    } else if (strcmp(output, "listening\n") == 0) {
        result = 1;
    } else if (strcmp(output, "learning\n") == 0) {
        result = 2;
    } else if (strcmp(output, "forwarding\n") == 0) {
        result = 3;
    } else if (strcmp(output, "disabled\n") == 0) {
        result = 4;
    } else {
        if (*output != '\"') {
            VLOG_ERR("handle_get_ulong_val_port_cmd %s\n", output);
            result = 0;
            goto send_reply;
        }

        errno = 0;
        result = strtoul(output + 1, &end_p, 10);
        if (end_p == (output + 1) || *end_p != '\"' || (result == ULONG_MAX && (errno == ERANGE))) {
            VLOG_ERR("Error occurred during converting string to int cmd\n");
            result = 0;
            goto send_reply;
        }
    }

send_reply:
    /* Compose and send reply. */
    reply = compose_reply(0);
    nl_msg_put_u32(reply, BRC_GENL_A_GET_ULONG, result);
    send_reply(reply, seq);

    free(output);
    return 0;
}

static int
handle_get_ulong_val_iface_cmd(struct ofpbuf *buffer, const char *sub_cmd)
{
    const char *br_name;
    uint32_t seq;
    char *output, *end_p = NULL;
    int error;
    unsigned long result;
    struct ofpbuf *reply;

    /* Parse Netlink command. */
    error = parse_command(buffer, &seq, &br_name, NULL, NULL, NULL, NULL, NULL);
    if (error) {
        return error;
    }

    output = capture_vsctl(vsctl_program, VSCTL_OPTIONS, "get", "Interface", br_name, sub_cmd, (char *) NULL);

    if (!output) {
        VLOG_ERR("handle_get_ulong_val_port_cmd has no output\n");
        result = 0;
        goto send_reply;
    }

    errno = 0;
    result = strtoul(output, &end_p, 10);

    if ((result == ULONG_MAX && (errno == ERANGE))) {
        VLOG_ERR("Error occurred during converting string to int cmd\n");
        result = 0;
        goto send_reply;
    }

send_reply:
    /* Compose and send reply. */
    reply = compose_reply(0);
    nl_msg_put_u32(reply, BRC_GENL_A_GET_ULONG, result);
    send_reply(reply, seq);

    free(output);
    return 0;
}

static int
handle_set_mc_snooping_flag_cmd(struct ofpbuf *buffer)
{
    char *str_key_value_type, *str_key_value_snooping;
    uint64_t ip_type, br_snooping;
    uint32_t seq;
    int error;

    error = parse_command(buffer, &seq, NULL, NULL, &br_snooping, NULL, &ip_type, NULL);

    if (!error) {
        str_key_value_type = xasprintf("%"PRIu64, ip_type);
        str_key_value_snooping = xasprintf("%"PRIu64, br_snooping);

        if (!run_vsctl(appctl_program,
                       "--", "mdb/mc-snooping-flag", str_key_value_type,
                        str_key_value_snooping, (char *) NULL)) {
            error = EINVAL;
        }
        send_simple_reply(seq, error);

        free(str_key_value_type);
        free(str_key_value_snooping);
    }
    return error;
}

static void set_bridge_parameter(const char *br_name, const char *param, unsigned long value)
{
    char *str_key_value = xasprintf("%s=%lu", param, value);
    run_vsctl(vsctl_program, VSCTL_OPTIONS, "--", "set", "Bridge", br_name, str_key_value, (char *) NULL);
    free(str_key_value);
}

static void set_port_parameter(const char *pr_name, const char *param, unsigned long value)
{
    char *str_key_value = xasprintf("%s=%lu", param, value);
    run_vsctl(vsctl_program, VSCTL_OPTIONS, "--", "set", "Port", pr_name, str_key_value, (char *) NULL);
    free(str_key_value);
}

static void set_default_parameters(const char *br_name)
{
    set_bridge_parameter(br_name, "other_config:stp-priority", STP_DEFAULT_BRIDGE_PRIORITY);
    set_bridge_parameter(br_name, "other_config:stp-max-age", STP_DEFAULT_MAX_AGE);
    set_bridge_parameter(br_name, "other_config:stp-hello-time", STP_DEFAULT_HELLO_TIME);
    set_bridge_parameter(br_name, "other_config:stp-forward-delay", STP_DEFAULT_FWD_DELAY);
    set_bridge_parameter(br_name, "other_config:mac-aging-time", DEFAULT_MAC_AGING_TIME);
}

static void set_default_port_parameters(const char *pr_name)
{
    set_port_parameter(pr_name, "other_config:stp-path-cost", STP_PATH_COST);
}

static bool
brc_recv_update__(struct ofpbuf *buffer)
{
    int net_id;

    for (;;) {
        int retval = nl_sock_recv(brc_sock, buffer, &net_id, false);
        switch (retval) {
        case 0:
            if (nl_msg_nlmsgerr(buffer, NULL)
                || nl_msg_nlmsghdr(buffer)->nlmsg_type == NLMSG_DONE) {
                break;
            }
            return true;

        case ENOBUFS:
            break;

        case EAGAIN:
            return false;

        default:
            VLOG_WARN_RL(&rl, "brc_recv_update: %s", ovs_strerror(retval));
            return false;
        }
    }
}

static void
brc_recv_update(void)
{
    struct genlmsghdr *genlmsghdr;
    uint64_t buffer_stub[1024 / 8];
    struct ofpbuf buffer;

    ofpbuf_use_stub(&buffer, buffer_stub, sizeof buffer_stub);
    if (!brc_recv_update__(&buffer)) {
        goto error;
    }

    genlmsghdr = nl_msg_genlmsghdr(&buffer);
    if (!genlmsghdr) {
        VLOG_WARN_RL(&rl, "received packet too short for generic NetLink");
        goto error;
    }

    if (nl_msg_nlmsghdr(&buffer)->nlmsg_type != brc_family) {
        VLOG_DBG_RL(&rl, "received type (%"PRIu16") != brcompat family (%d)",
                nl_msg_nlmsghdr(&buffer)->nlmsg_type, brc_family);
        goto error;
    }

    /* Service all pending network device notifications before executing the
     * command.  This is very important to avoid a race in a scenario like the
     * following, which is what happens with XenServer Tools version 5.0.0
     * during boot of a Windows VM:
     *
     *      1. Create tap1.0 and vif1.0.
     *      2. Delete tap1.0.
     *      3. Delete vif1.0.
     *      4. Re-create vif1.0.
     *
     * We must process the network device notification from step 3 before we
     * process the brctl command from step 4.  If we process them in the
     * reverse order, then step 4 completes as a no-op but step 3 then deletes
     * the port that was just added.
     *
     * (XenServer Tools 5.5.0 does not exhibit this behavior, and neither does
     * a VM without Tools installed at all.)
     */
    rtnetlink_run();

    switch (genlmsghdr->cmd) {
    case BRC_GENL_C_DP_ADD:
        handle_bridge_cmd(&buffer, true);
        break;

    case BRC_GENL_C_DP_DEL:
        handle_bridge_cmd(&buffer, false);
        break;

    case BRC_GENL_C_PORT_ADD:
        handle_port_cmd(&buffer, true);
        break;

    case BRC_GENL_C_PORT_DEL:
        handle_port_cmd(&buffer, false);
        break;

    case BRC_GENL_C_FDB_QUERY:
        handle_fdb_query_cmd(&buffer);
        break;

    case BRC_GENL_C_GET_BRIDGES:
        handle_get_bridges_cmd(&buffer);
        break;

    case BRC_GENL_C_GET_PORTS:
        handle_get_ports_cmd(&buffer);
        break;

    case BRC_GENL_C_SET_AGEING_TIME:
        handle_set_ulong_val_cmd(&buffer, "mac-aging-time");
        break;

    case BRC_GENL_C_SET_BRIDGE_FORWARD_DELAY:
        handle_set_ulong_val_cmd(&buffer, "stp-forward-delay");
        break;

    case BRC_GENL_C_SET_BRIDGE_HELLO_TIME:
        handle_set_ulong_val_cmd(&buffer, "stp-hello-time");
        break;

    case BRC_GENL_C_SET_BRIDGE_MAX_AGE:
        handle_set_ulong_val_cmd(&buffer, "stp-max-age");
        break;

    case BRC_GENL_C_SET_BRIDGE_PRIORITY:
        handle_set_ulong_val_cmd(&buffer, "stp-priority");
        break;

    case BRC_GENL_C_SET_BRIDGE_STP_STATE:
        handle_set_boolean_val_cmd(&buffer, "stp_enable");
        break;

    case BRC_GENL_C_GET_BRIDGE_PRIORITY:
        handle_get_ulong_val_cmd(&buffer, "other_config:stp-priority");
        break;

    case BRC_GENL_C_GET_BRIDGE_STP_STATE:
        handle_get_ulong_val_cmd(&buffer, "stp_enable");
        break;

    case BRC_GENL_C_GET_BRIDGE_HELLO_TIME:
        handle_get_ulong_val_cmd(&buffer, "other_config:stp-hello-time");
        break;

    case BRC_GENL_C_GET_BRIDGE_FORWARD_DELAY:
        handle_get_ulong_val_cmd(&buffer, "other_config:stp-forward-delay");
        break;

    case BRC_GENL_C_GET_BRIDGE_MAX_AGE:
        handle_get_ulong_val_cmd(&buffer, "other_config:stp-max-age");
        break;

    case BRC_GENL_C_GET_BRIDGE_MULTICAST_SNOOPING:
        handle_get_ulong_val_cmd(&buffer, "mcast_snooping_enable");
        break;

    case BRC_GENL_C_SET_BRIDGE_MULTICAST_SNOOPING:
        handle_set_boolean_val_cmd(&buffer, "mcast_snooping_enable");
        break;

    case BRC_GENL_C_GET_AGEING_TIME:
        handle_get_ulong_val_cmd(&buffer, "other_config:mac-aging-time");
        break;

    case BRC_GENL_C_GET_BRIDGE_ROOT_ID:
        handle_get_string_value(&buffer, "status:stp_designated_root");
        break;

    case BRC_GENL_C_GET_PORT_STATE:
        handle_get_ulong_val_port_cmd(&buffer, "status:stp_state");
        break;

    case BRC_GENL_C_GET_PORT_PORT_NO:
        handle_get_ulong_val_iface_cmd(&buffer, "ofport");
        break;

    case BRC_GENL_C_GET_PORT_PATH_COST:
        handle_get_ulong_val_port_cmd(&buffer, "other_config:stp-path-cost");
        break;

    case BRC_GENL_C_SET_PORT_PATH_COST:
        handle_set_ulong_val_port_cmd(&buffer, "stp-path-cost");
        break;
    case BRC_GENL_C_SET_MC_SNOOPING_FLAG:
        handle_set_mc_snooping_flag_cmd(&buffer);
        break;
    case BRC_GENL_C_GET_BRIDGE_BY_PORT:
        handle_get_bridge_name_value(&buffer);
        break;
    case BRC_GENL_C_GET_BRIDGE_EXISTS:
        handle_get_bridge_exists(&buffer);
        break;

    /* seamless-ovs { */
    case BRC_GENL_C_MG_ADD:
        handle_mg_add_del_cmd(&buffer, true);
        break;

    case BRC_GENL_C_MG_DEL:
        handle_mg_add_del_cmd(&buffer, false);
        break;

    case BRC_GENL_C_SET_MCSNOOP_ROUT_PORT:
        handle_set_mc_router_port_cmd(&buffer);
        break;

    case BRC_GENL_C_SET_MAC_ADDR:
        handle_set_mac_addr_cmd(&buffer);
        break;

    case BRC_GENL_C_SET_PORT_MC_SNOOPING_FLOOD_REPORTS:
        handle_set_boolean_val_port_cmd(&buffer, "other-config:mcast-snooping-flood-reports");
        break;

    case BRC_GENL_C_SET_MTU:
        handle_set_ulong_val_interface_cmd(&buffer, "mtu_request");
        break;

    case BRC_GENL_C_SET_PORT_HAIRPIN_MODE:
        handle_set_boolean_val_port_cmd(&buffer, "other-config:hairpin-mode");
        break;
    /* } seamless-ovs */

    default:
        VLOG_WARN_RL(&rl, "received unknown brc netlink command: %d\n",
                     genlmsghdr->cmd);
        break;
    }

error:
    ofpbuf_uninit(&buffer);
}

static void
netdev_changed_cb(const struct rtnetlink_change *change,
                  void *aux OVS_UNUSED)
{
    char br_name[IFNAMSIZ];
    const char *port_name;

    if (!change) {
        VLOG_WARN_RL(&rl, "network monitor socket overflowed");
        return;
    }

    if (change->nlmsg_type != RTM_DELLINK || !change->master_ifindex) {
        return;
    }

    port_name = change->ifname;
    if (!if_indextoname(change->master_ifindex, br_name)) {
        return;
    }

    VLOG_INFO("network device %s destroyed, removing from bridge %s",
              port_name, br_name);

    run_vsctl(vsctl_program, VSCTL_OPTIONS,
              "--", "--if-exists", "del-port", port_name,
              "--", "comment", "ovs-brcompatd:", port_name, "disappeared",
              (char *) NULL);
}

int
main(int argc, char *argv[])
{
    struct nln_notifier *link_notifier;
    struct unixctl_server *unixctl;
    int retval;

    ovs_cmdl_proctitle_init(argc, argv);
    set_program_name(argv[0]);
    vlog_set_levels(NULL, VLF_ANY_DESTINATION, VLL_WARN);
    vlog_set_levels_from_string_assert("reconnect:dbg");

    VLOG_INFO("\nBridge compatibility daemon is starting ...\n");

    parse_options(argc, argv);
    signal(SIGPIPE, SIG_IGN);
    process_init();

    daemonize_start(false);

    retval = unixctl_server_create(NULL, &unixctl);
    if (retval) {
        exit(EXIT_FAILURE);
    }

    if (brc_open(&brc_sock)) {
        VLOG_FATAL("could not open brcompat socket.  Check "
                   "\"brcompat\" kernel module.");
    }

    link_notifier = rtnetlink_notifier_create(netdev_changed_cb, NULL);

    daemonize_complete();

    for (;;) {
        unixctl_server_run(unixctl);
        rtnetlink_run();
        brc_recv_update();

        netdev_run();

        nl_sock_wait(brc_sock, POLLIN);
        unixctl_server_wait(unixctl);
        rtnetlink_wait();
        netdev_wait();
        poll_block();
    }

    rtnetlink_notifier_destroy(link_notifier);

    return 0;
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        OPT_APPCTL,
        OPT_VSCTL,
        VLOG_OPTION_ENUMS,
//        LEAK_CHECKER_OPTION_ENUMS,
        DAEMON_OPTION_ENUMS
    };
    static struct option long_options[] = {
        {"help",             no_argument, NULL, 'h'},
        {"version",          no_argument, NULL, 'V'},
        {"appctl",           required_argument, NULL, OPT_APPCTL},
        {"vsctl",            required_argument, NULL, OPT_VSCTL},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
//        LEAK_CHECKER_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);
    const char *appctl = "ovs-appctl";
    const char *vsctl = "ovs-vsctl";

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage();

        case 'V':
            ovs_print_version(0, 0);
            exit(EXIT_SUCCESS);

        case OPT_APPCTL:
            appctl = optarg;
            break;

        case OPT_VSCTL:
            vsctl = optarg;
            break;

        VLOG_OPTION_HANDLERS
        DAEMON_OPTION_HANDLERS
//        LEAK_CHECKER_OPTION_HANDLERS

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);

    appctl_program = process_search_path(appctl);
    if (!appctl_program) {
        VLOG_FATAL("%s: not found in $PATH (use --appctl to specify an "
                   "alternate location)", appctl);
    }

    vsctl_program = process_search_path(vsctl);
    if (!vsctl_program) {
        VLOG_FATAL("%s: not found in $PATH (use --vsctl to specify an "
                   "alternate location)", vsctl);
    }

    if (argc != optind) {
        VLOG_FATAL("no non-option arguments are supported; "
                   "use --help for usage");
    }
}

static void
usage(void)
{
    printf("%s: bridge compatibility front-end for ovs-vswitchd\n"
           "usage: %s [OPTIONS]\n",
           program_name, program_name);
    printf("\nConfiguration options:\n"
           "  --appctl=PROGRAM        overrides $PATH for finding ovs-appctl\n"
           "  --vsctl=PROGRAM         overrides $PATH for finding ovs-vsctl\n"
          );
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
//    leak_checker_usage();
    exit(EXIT_SUCCESS);
}
