/*
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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (c) 2019 Arista Networks, Inc.  All rights reserved.
 */

#ifndef BFLBM_H
#define BFLBM_H

#include <linux/netfilter.h>
#include <linux/version.h>

#define BHD_LBDATA 1
#define BRH_SNAT 2
#define BRH_DECAP 4

#define IPV6_HDR_LEN 40
#define VXLAN_FLAGS 0x08000000

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) "[LBM]: " fmt
/* Follow the kernel trace levels */
#define LBM_WARN 4
#define LBM_NOTICE 5
#define LBM_INFO 6
#define LBM_DEBUG 7

/* Global module arguments */
extern int VERBOSE;
extern int MARK_OFFSET;
extern int DECAP_ONLY;
extern int INPUT_PORT;
extern char *INTF_PREFIX;
extern int INTF_PREFIX_LEN;
extern int quic_ports[32];
extern int quic_ports_count;

/* commit e21951212f03 ("net: move make_writable helper into common code") */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 18, 0)
#define skb_ensure_writable(skb, len) (!skb_make_writable(skb, len))
#endif

/* Prototypes */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
unsigned int decap_hook_ip4(void *priv, struct sk_buff *pskb,
                            const struct nf_hook_state *state);
unsigned int decap_hook_ip6(void *priv, struct sk_buff *pskb,
                            const struct nf_hook_state *state);
unsigned int reflect_hook_ip4(void *priv, struct sk_buff *pskb,
                              const struct nf_hook_state *state);
unsigned int reflect_hook_ip6(void *priv, struct sk_buff *pskb,
                              const struct nf_hook_state *state);
unsigned int snat_hook_ip4(void *priv, struct sk_buff *pskb,
                           const struct nf_hook_state *state);

unsigned int snat_hook_ip6(void *priv, struct sk_buff *pskb,
                           const struct nf_hook_state *state);
#else

unsigned int decap_hook_ip4(unsigned int hooknum, struct sk_buff *pskb,
                            const struct net_device *in,
                            const struct net_device *out,
                            int (*okfn)(struct sk_buff *));
unsigned int decap_hook_ip6(unsigned int hooknum, struct sk_buff *pskb,
                            const struct net_device *in,
                            const struct net_device *out,
                            int (*okfn)(struct sk_buff *));
unsigned int reflect_hook_ip4(unsigned int hooknum, struct sk_buff *pskb,
                              const struct net_device *in,
                              const struct net_device *out,
                              int (*okfn)(struct sk_buff *));
unsigned int reflect_hook_ip6(unsigned int hooknum, struct sk_buff *pskb,
                              const struct net_device *in,
                              const struct net_device *out,
                              int (*okfn)(struct sk_buff *));
unsigned int snat_hook_ip4(unsigned int hooknum, struct sk_buff *pskb,
                           const struct net_device *in,
                           const struct net_device *out,
                           int (*okfn)(struct sk_buff *));

unsigned int snat_hook_ip6(unsigned int hooknum, struct sk_buff *pskb,
                           const struct net_device *in,
                           const struct net_device *out,
                           int (*okfn)(struct sk_buff *));
#endif

#endif /* BFLBM_H */
