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
 * Copyright (c) 2019 Arista Networks, Inc. All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/version.h>
#include <net/vxlan.h>
#include <net/icmp.h>
#include <net/netfilter/nf_conntrack_tuple.h>
#include <net/netfilter/nf_conntrack.h>

#include "bflbm.h"
#include "bflbm_utils.h"

/* Verify that this is a packet from the load balancer */
static struct outer_packet_ip4 *examine_outer_packet_ip4(struct sk_buff *skb)
{
	struct outer_packet_ip4 *opkt = NULL;

	if (!pskb_may_pull(skb, sizeof(struct outer_packet_ip4))) {
		if (VERBOSE >= LBM_INFO)
			pr_info("Could not linearize outer pkt");
		return NULL;
	}

	opkt = (struct outer_packet_ip4 *) skb_network_header(skb);
	/* If packet is not UDP or on the port specified, let it pass */
	if (opkt->ip_header.protocol != IPPROTO_UDP ||
		opkt->udp_header.dest != htons(INPUT_PORT)) {
		return NULL;
	}

	if (VERBOSE >= LBM_INFO)
		pr_info("Received encaped packet\n");

	return opkt;
}

static struct inner_packet_ip4 *decap_and_mark_ip4(struct sk_buff *skb,
					   int inner_offset)
{
	struct inner_packet_ip4 *ipkt = NULL;
	bool icmp_err_with_tcp = false;
	unsigned int netSkbLen = inner_offset + sizeof(struct iphdr);

	/* Remove outer packet headers */
	skb_pull(skb, sizeof(struct outer_packet_ip4));

	if (!pskb_may_pull(skb, netSkbLen)) {
		if (VERBOSE >= LBM_WARN)
			pr_info("Failed to pull inner ip header\n");
		return NULL;
	}

	skb_set_mac_header(skb, 0);

	/* Remove inner packet ethernet header */
	skb_pull(skb, inner_offset);
	netSkbLen -= inner_offset;

	skb_set_network_header(skb, 0);

	skb_set_transport_header(skb, ip_hdr(skb)->ihl * 4);

	ipkt = (struct inner_packet_ip4 *) ip_hdr(skb);

	// If this is an ICMP error packet for fragmentation needed or TTL
	// exceeded and if the inner packet is TCP, then we mark it.  Later
	// in reflect hook, if we dont find a connection corresponding to
	// this packet, we are going to reflect the packet
	if (ipkt->ip_header.protocol == IPPROTO_ICMP) {
		struct icmphdr *icmp_header = NULL;

		if (!pskb_may_pull(skb, netSkbLen + sizeof(struct icmphdr))) {
			if (VERBOSE >= LBM_WARN)
				pr_info("Failed to pull inner icmp header\n");
			return NULL;
		}

		icmp_header = icmp_hdr(skb);
		if (VERBOSE >= LBM_DEBUG)
			pr_info("ICMP type %d code %d\n",
				icmp_header->type, icmp_header->code);
		if ((icmp_header->type == ICMP_DEST_UNREACH) ||
			(icmp_header->type == ICMP_TIME_EXCEEDED &&
			icmp_header->code == ICMP_EXC_TTL)) {
			struct nf_conntrack_tuple icmp_payload;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0) \
		|| (RHEL_MAJOR >= 7 && RHEL_MINOR >= 7)
			if (nf_ct_get_tuplepr(skb,
				skb_network_offset(skb) +
				ip_hdrlen(skb)
				+ sizeof(struct icmphdr),
				PF_INET, dev_net(skb->dev), &icmp_payload)) {
#else
			if (nf_ct_get_tuplepr(skb,
				skb_network_offset(skb) +
				ip_hdrlen(skb)
				+ sizeof(struct icmphdr),
				PF_INET, &icmp_payload)) {
#endif

				if (VERBOSE >= LBM_DEBUG)
					pr_info("Inner proto %d\n",
						icmp_payload.dst.protonum);
				if (icmp_payload.dst.protonum == IPPROTO_TCP)
					icmp_err_with_tcp = true;
			}
		}
	} else if (ipkt->ip_header.protocol == IPPROTO_TCP) {
		if (!pskb_may_pull(skb, netSkbLen + sizeof(struct tcphdr))) {
			if (VERBOSE >= LBM_WARN)
				pr_info("Failed to pull inner tcp header\n");
			return NULL;
		}
	}  else if (ipkt->ip_header.protocol == IPPROTO_UDP) {
		if (!pskb_may_pull(skb, netSkbLen + sizeof(struct udphdr))) {
			if (VERBOSE >= LBM_WARN)
				pr_info("Failed to pull inner udp header\n");
			return NULL;
		}
	}
	clear_protocol_mark(skb);

	//
	if ((ipkt->ip_header.protocol == IPPROTO_TCP ||
		icmp_err_with_tcp) && !DECAP_ONLY) {
		set_protocol_mark(skb, BHD_LBDATA);
	}

	if ((ipkt->ip_header.protocol == IPPROTO_UDP ) && !DECAP_ONLY) {
		set_protocol_mark(skb, BHD_LBDATA);
	}

	// Indicate this was a pkt we decap'ed.
	set_protocol_mark(skb, BRH_DECAP);
	return ipkt;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
unsigned int decap_hook_ip4(void *priv,
				struct sk_buff *pskb,
				const struct nf_hook_state *state)
{
	struct outer_packet_ip4 *opkt = NULL;
	struct inner_packet_ip4 *ipkt = NULL;

	int inner_offset = 0;
	unsigned char *data_ptr = NULL;
	// Only consider decaping if the incoming interface starts with
	// INTF_PREFIX
	if (!state || !state->in ||
		memcmp(state->in->name, INTF_PREFIX, INTF_PREFIX_LEN) != 0)
		return NF_ACCEPT;

#else
unsigned int decap_hook_ip4(unsigned int hooknum,
				struct sk_buff *pskb,
				const struct net_device *in,
				const struct net_device *out,
				int (*okfn)(struct sk_buff *))
{
	struct outer_packet_ip4 *opkt = NULL;
	struct inner_packet_ip4 *ipkt = NULL;

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

	opkt = examine_outer_packet_ip4(pskb);
	if (opkt == NULL)
		return NF_ACCEPT;

	data_ptr += sizeof(struct outer_packet_ip4);

	/* Potential vlan header */
	inner_offset = find_inner_offset(data_ptr);

	/* Decap up to the inner IP header */
	ipkt = decap_and_mark_ip4(pskb, inner_offset);
	if (VERBOSE >= LBM_DEBUG) {
		if (ipkt != NULL) {
		/* Only print if we could linearize the pkt */
			printk_outer_packet_ip4(opkt);
			printk_inner_packet_ip4(ipkt);
		}
	}
	return NF_ACCEPT;
}

