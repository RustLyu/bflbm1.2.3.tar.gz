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

#include <linux/icmpv6.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>
#include <linux/version.h>
#include <net/vxlan.h>
#include <net/netfilter/nf_conntrack_tuple.h>
#include <net/netfilter/nf_conntrack.h>

#include "bflbm.h"
#include "bflbm_utils.h"

/* Verify that this is a packet from the load balancer */
static struct outer_packet_ip6 *examine_outer_packet_ip6(struct sk_buff *skb)
{
	struct outer_packet_ip6 *opkt = NULL;

	if (!pskb_may_pull(skb, sizeof(struct outer_packet_ip6))) {
		if (VERBOSE >= LBM_INFO)
			pr_info("Could not linearize outer v6 pkt");
		return NULL;
	}

	opkt = (struct outer_packet_ip6 *) skb_network_header(skb);
	/* If packet is not UDP or on the port specified, let it pass */
	if (opkt->ip_header.nexthdr != IPPROTO_UDP)
		return NULL;
	if (opkt->udp_header.dest != htons(INPUT_PORT))
		return NULL;

	if (VERBOSE >= LBM_INFO)
		pr_info("Received encaped packet\n");

	return opkt;
}

static struct inner_packet_ip6 *decap_and_mark_ip6(struct sk_buff *skb,
					   int inner_offset)
{
	struct inner_packet_ip6 *ipkt = NULL;
	struct ipv6hdr *inner_ip = NULL;
	bool icmp6_err_with_tcp = false;
	__be16 frag_off = 0;
	u8 nexthdr = 0;
	u32 l4_off = 0;
	unsigned int netSkbLen = inner_offset + sizeof(struct ipv6hdr);

	/* Remove outer packet headers */
	skb_pull(skb, sizeof(struct outer_packet_ip6));

	/* Make sure the nested ip is present */
	if (!pskb_may_pull(skb, netSkbLen)) {
		if (VERBOSE >= LBM_WARN)
			pr_info("Failed to pull in inner ipv6 header\n");
		return NULL;
	}

	skb_set_mac_header(skb, 0);
	/* Remove inner packet ethernet header */
	skb_pull(skb, inner_offset);
	netSkbLen -= inner_offset;
	skb_set_network_header(skb, 0);

	/* determining the offset to skip IPV6 extension headers */
	inner_ip = ipv6_hdr(skb);
	nexthdr = inner_ip->nexthdr;
	l4_off = ipv6_skip_exthdr(skb,
			sizeof(struct ipv6hdr), &nexthdr, &frag_off);
	skb_set_transport_header(skb, l4_off);

	ipkt = (struct inner_packet_ip6 *) ipv6_hdr(skb);

	// If this is an ICMP error packet for fragmentation needed or TTL
	// exceeded and if the inner packet is TCP, then we mark it.  Later
	// in reflect hook, if we dont find a connection corresponding to
	// this packet, we are going to reflect the packet
	if (ipkt->ip_header.nexthdr == IPPROTO_ICMPV6) {
		struct icmp6hdr *icmp6_header = NULL;

		if (!pskb_may_pull(skb, netSkbLen + sizeof(struct icmp6hdr))) {
			if (VERBOSE >= LBM_WARN)
				pr_info("Failed to pull inner v6 icmp header\n");
			return NULL;
		}

		icmp6_header = icmp6_hdr(skb);
		if (VERBOSE >= LBM_DEBUG)
			pr_info("ICMPv6 type %d code %d\n",
			icmp6_header->icmp6_type, icmp6_header->icmp6_code);
		if ((icmp6_header->icmp6_type == ICMPV6_DEST_UNREACH) ||
			(icmp6_header->icmp6_type == ICMPV6_PKT_TOOBIG) ||
			(icmp6_header->icmp6_type == ICMPV6_TIME_EXCEED &&
			icmp6_header->icmp6_code == ICMPV6_EXC_HOPLIMIT)) {
			struct nf_conntrack_tuple icmp6_payload;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0) \
		|| (RHEL_MAJOR >= 7 && RHEL_MINOR >= 7)
			if (nf_ct_get_tuplepr(skb,
				skb_network_offset(skb) +
				IPV6_HDR_LEN
				+ sizeof(struct icmp6hdr),
				PF_INET6, dev_net(skb->dev), &icmp6_payload)) {
#else
			if (nf_ct_get_tuplepr(skb,
				skb_network_offset(skb) +
				IPV6_HDR_LEN
				+ sizeof(struct icmp6hdr),
				PF_INET6, &icmp6_payload)) {
#endif

				if (VERBOSE >= LBM_DEBUG)
					pr_info("Inner proto %d\n",
						icmp6_payload.dst.protonum);
				if (icmp6_payload.dst.protonum == IPPROTO_TCP)
					icmp6_err_with_tcp = true;
			}
		}
	} else if (ipkt->ip_header.nexthdr == IPPROTO_TCP) {
		if (!pskb_may_pull(skb, netSkbLen + sizeof(struct tcphdr))) {
			if (VERBOSE >= LBM_WARN)
				pr_info("Failed to pull inner tcp header\n");
			return NULL;
		}
	}
	clear_protocol_mark(skb);

	if ((ipkt->ip_header.nexthdr == IPPROTO_TCP ||
		icmp6_err_with_tcp) && !DECAP_ONLY) {
		set_protocol_mark(skb, BDH_TCP);
	}

	// If the next header is a fragment, check if the header next to it
	// is a TCP header
	if (ipkt->ip_header.nexthdr == IPPROTO_FRAGMENT) {
		struct frag_hdr *fptr;

		fptr = (struct frag_hdr *) (skb_network_header(skb) +
			IPV6_HDR_LEN);
		if (fptr->nexthdr == IPPROTO_TCP)
			set_protocol_mark(skb, BDH_TCP);
	}

	// Indicate this was a pkt we decap'ed.
	set_protocol_mark(skb, BRH_DECAP);
	return ipkt;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
unsigned int decap_hook_ip6(void *priv,
				struct sk_buff *pskb,
				const struct nf_hook_state *state)
{
	struct outer_packet_ip6 *opkt = NULL;
	struct inner_packet_ip6 *ipkt = NULL;

	int inner_offset = 0;
	unsigned char *data_ptr = NULL;
	// Only consider decaping if the incoming interface starts with
	// INTF_PREFIX
	if (!state || !state->in ||
		memcmp(state->in->name, INTF_PREFIX, INTF_PREFIX_LEN) != 0)
		return NF_ACCEPT;

#else
unsigned int decap_hook_ip6(unsigned int hooknum,
				struct sk_buff *pskb,
				const struct net_device *in,
				const struct net_device *out,
				int (*okfn)(struct sk_buff *))
{
	struct outer_packet_ip6 *opkt = NULL;
	struct inner_packet_ip6 *ipkt = NULL;

	int inner_offset = 0;
	unsigned char *data_ptr = NULL;

	// Only consider decaping if the incoming interface starts with
	// INTF_PREFIX
	if (!in || memcmp(in->name, INTF_PREFIX, INTF_PREFIX_LEN) != 0)
		return NF_ACCEPT;
#endif

	if (!pskb || skb_ensure_writable(pskb, 0))
		return NF_ACCEPT;

	data_ptr = pskb->data;

	opkt = examine_outer_packet_ip6(pskb);
	if (opkt == NULL)
		return NF_ACCEPT;
	data_ptr += sizeof(struct outer_packet_ip6);
	inner_offset = find_inner_offset(data_ptr);

	/* Decap up to the inner IPv6 header */
	ipkt = decap_and_mark_ip6(pskb, inner_offset);
	if (VERBOSE >= LBM_DEBUG) {
		if (ipkt != NULL) {
		/* Only print if we could linearize the pkt */
			printk_outer_packet_ip6(opkt);
			printk_inner_packet_ip6(ipkt);
		}
	}
	return NF_ACCEPT;
}
