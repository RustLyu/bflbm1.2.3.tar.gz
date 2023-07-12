/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (c) 2020 Arista Networks, Inc. All rights reserved.
 */

#define BFLBM_INIT
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/version.h>
#include <net/icmp.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_tuple.h>
#include <net/vxlan.h>

#include "bflbm.h"

char *VERSION = "1.2.3-quic";

/* Module Arguments */
int VERBOSE = 0;
module_param(VERBOSE, int, 0x0);
MODULE_PARM_DESC(
    VERBOSE, "Print debug statements to the message buffer, options: [0/1/2]");

int MARK_OFFSET = 16;
module_param(MARK_OFFSET, int, 0x0);
MODULE_PARM_DESC(
    MARK_OFFSET,
    "Offset of the bits using in the 32 bit skb->mark field. Two bits "
    "are used, with the default being bits 16 and 17, options: 0-30");

int DECAP_ONLY = 0;
module_param(DECAP_ONLY, int, 0x0);
MODULE_PARM_DESC(
    DECAP_ONLY,
    "Only decap the incoming packets, do not reflect, options: [0/1]");

int INPUT_PORT = 4789;
module_param(INPUT_PORT, int, 0x0);
MODULE_PARM_DESC(
    INPUT_PORT,
    "Specify the UDP dest port for encapsulated traffic, default: 4789");

char *INTF_PREFIX = "";
int INTF_PREFIX_LEN = 0;
module_param(INTF_PREFIX, charp, 0000);
MODULE_PARM_DESC(
    INTF_PREFIX,
    "The prefix of the interface name that should execute the netfilter hooks");

int ALL_NETNS = 0;
module_param(ALL_NETNS, int, 0x0);
MODULE_PARM_DESC(
    ALL_NETNS,
    "Enable the module for all network namespaces when kernel version"
    " is greater than 4.13.0, options: [0/1]");

int quic_ports[32];
int quic_ports_count = 0;
module_param_array(quic_ports, int, &quic_ports_count, 0);
MODULE_PARM_DESC(quic_ports,
                 "List of UDP ports to apply gQUIC-43 gracefull [443,80]");

static struct nf_hook_ops decap_net_filter_opts = {
    .hook = (nf_hookfn *)decap_hook_ip4,
    .hooknum = NF_INET_PRE_ROUTING,
    .pf = PF_INET,                              /* IPV4 packets */
    .priority = NF_IP_PRI_CONNTRACK_DEFRAG - 1, /* Just before Defrag */
};

static struct nf_hook_ops reflect_net_filter_opts = {
    .hook = (nf_hookfn *)reflect_hook_ip4,
    .hooknum = NF_INET_PRE_ROUTING,
    .pf = PF_INET,                    /* IPV4 packets */
    .priority = NF_IP_PRI_NAT_DST - 1 /* Just before DNAT */
};

static struct nf_hook_ops snat_net_filter_opts = {
    .hook = (nf_hookfn *)snat_hook_ip4,
    .hooknum = NF_INET_POST_ROUTING,
    .pf = PF_INET,                    /* IPV4 packets */
    .priority = NF_IP_PRI_NAT_SRC - 1 /* Just before SNAT */
};

static struct nf_hook_ops decap_net6_filter_opts = {
    .hook = (nf_hookfn *)decap_hook_ip6,
    .hooknum = NF_INET_PRE_ROUTING,
    .pf = PF_INET6,                              /* IPV6 packets */
    .priority = NF_IP6_PRI_CONNTRACK_DEFRAG - 1, /* Just before Defrag */
};

static struct nf_hook_ops reflect_net6_filter_opts = {
    .hook = (nf_hookfn *)reflect_hook_ip6,
    .hooknum = NF_INET_PRE_ROUTING,
    .pf = PF_INET6,                    /* IPV6 packets */
    .priority = NF_IP6_PRI_NAT_DST - 1 /* Just before DNAT */
};

static struct nf_hook_ops snat_net6_filter_opts = {
    .hook = (nf_hookfn *)snat_hook_ip6,
    .hooknum = NF_INET_POST_ROUTING,
    .pf = PF_INET6,                    /* IPV6 packets */
    .priority = NF_IP6_PRI_NAT_SRC - 1 /* Just before SNAT */
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
static int __net_init bflbm_nf_register(struct net *net) {
  nf_register_net_hook(net, &decap_net_filter_opts);
  nf_register_net_hook(net, &decap_net6_filter_opts);
  if (DECAP_ONLY == 0) {
    nf_register_net_hook(net, &reflect_net_filter_opts);
    nf_register_net_hook(net, &reflect_net6_filter_opts);
  }
  nf_register_net_hook(net, &snat_net_filter_opts);
  nf_register_net_hook(net, &snat_net6_filter_opts);
  return 0;
}

static void __net_exit bflbm_nf_unregister(struct net *net) {
  nf_unregister_net_hook(net, &decap_net_filter_opts);
  nf_unregister_net_hook(net, &decap_net6_filter_opts);
  if (DECAP_ONLY == 0) {
    nf_unregister_net_hook(net, &reflect_net_filter_opts);
    nf_unregister_net_hook(net, &reflect_net6_filter_opts);
  }
  nf_unregister_net_hook(net, &snat_net_filter_opts);
  nf_unregister_net_hook(net, &snat_net6_filter_opts);
}

static struct pernet_operations net_ops = {
    .init = bflbm_nf_register,
    .exit = bflbm_nf_unregister,
};
#endif

static int __init balancer_init(void) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
  if (ALL_NETNS == 1)
    register_pernet_subsys(&net_ops);
  else
    bflbm_nf_register(&init_net);
#else
  nf_register_hook(&decap_net_filter_opts);
  nf_register_hook(&decap_net6_filter_opts);
  if (DECAP_ONLY == 0) {
    nf_register_hook(&reflect_net_filter_opts);
    nf_register_hook(&reflect_net6_filter_opts);
  }
  nf_register_hook(&snat_net_filter_opts);
  nf_register_hook(&snat_net6_filter_opts);
#endif
  pr_info("--------------------------------------\n");
  pr_info("Loading 7170 Load Balancing Module\n");
  pr_info("   Version: %s\n", VERSION);
  pr_info("   ALL_NETNS: %d\n", ALL_NETNS);
  pr_info("   VERBOSE: %d, DECAP_ONLY: %d\n", VERBOSE, DECAP_ONLY);
  pr_info("   MARK_OFFSET: %d, INPUT_PORT: %-5d\n", MARK_OFFSET, INPUT_PORT);
  pr_info("   INTF_PREFIX: %s\n", INTF_PREFIX);
  pr_info("    - Decap Hook   [BDH]\n");
  pr_info("    - SNAT Hook    [BSH]\n");
  if (DECAP_ONLY == 0)
    pr_info("    - Reflect Hook [BRH]\n");


  if (DECAP_ONLY == 0) {
    if (quic_ports_count < 1) {
      quic_ports_count = 2;
      quic_ports[0] = 443;
      quic_ports[1] = 80;
    }

    pr_info("   quic_ports:\n");
    for (int i = 0; i < quic_ports_count; i++) {
      pr_info("    - %d\n", quic_ports[i]);
      // and convert to network order
      quic_ports[i] = htons(quic_ports[i]);
    }
  }

  INTF_PREFIX_LEN = strlen(INTF_PREFIX);
  if (IFNAMSIZ < INTF_PREFIX_LEN)
    INTF_PREFIX_LEN = IFNAMSIZ;
  return 0;
}

static void __exit balancer_cleanup(void) {
#if KERNEL_VERSION(4, 13, 0) <= LINUX_VERSION_CODE
  if (ALL_NETNS == 1)
    unregister_pernet_subsys(&net_ops);
  else
    bflbm_nf_unregister(&init_net);
#else
  nf_unregister_hook(&decap_net_filter_opts);
  nf_unregister_hook(&decap_net6_filter_opts);
  if (DECAP_ONLY == 0) {
    nf_unregister_hook(&reflect_net_filter_opts);
    nf_unregister_hook(&reflect_net6_filter_opts);
  }
  nf_unregister_hook(&snat_net6_filter_opts);
  nf_unregister_hook(&snat_net_filter_opts);
#endif
  pr_info("---------------------------------------\n");
  pr_info("Removing 7170 Load Balancing Module\n");
}

module_init(balancer_init);
module_exit(balancer_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arista Networks");
