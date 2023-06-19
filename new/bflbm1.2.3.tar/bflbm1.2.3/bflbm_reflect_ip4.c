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

#include <linux/kernel.h>
#include <net/netfilter/nf_conntrack.h>
#include "bflbm.h"
#include "bflbm_utils.h"
#include <net/icmp.h>

void reflect_packet_ip4(struct sk_buff *pskb, int inner_ip_len)
{
	struct outer_packet_ip4 *opkt = NULL;
	int offset;
	char *eth_ptr = NULL;

	if (skb_ensure_writable(pskb, 0))
		return;
	/* Determine offset of outer packet and inner eth header */
	offset = sizeof(struct outer_packet_ip4);
	eth_ptr = skb_mac_header(pskb);
	offset += find_inner_offset(eth_ptr);
	/* Move packet up to the outer IP header */
	skb_push(pskb, offset);

	skb_set_network_header(pskb, 0);
	opkt = (struct outer_packet_ip4 *) skb_network_header(pskb);
	skb_set_transport_header(pskb, opkt->ip_header.ihl * 4);
	/* Clear udp checksum */
	opkt->udp_header.check = 0;
	/* Store the daddr in the first four bytes of the inner eth header */
	memcpy(eth_ptr, &(opkt->ip_header.daddr), sizeof(__be32));
	/* Mangle the dest ip */
	opkt->ip_header.daddr = opkt->ip_header.saddr;
	opkt->ip_header.check = 0;
	/* Set the mark for the SNAT hook */
	set_protocol_mark(pskb, BRH_SNAT);
	/*
	 * Adjust the total-length value in the outer IP header. This is needed
	 * for the case where we received IP fragments from the load-balancer
	 * and after reassembly, figured out that we are not the right server.
	 * total-length = outer-ip (20) + outer-udp (8) + vxlan (8) +
	 *                inner-eth (14) + inner-ip-total-length
	 * We also update the udp header length for the same reason.
	 */
	opkt->ip_header.tot_len = htons(inner_ip_len + 50);
	opkt->udp_header.len = htons(inner_ip_len + 30);
	if (VERBOSE >= LBM_DEBUG)
		printk_outer_packet_ip4(opkt);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
unsigned int reflect_hook_ip4(void *priv,
			  struct sk_buff *pskb,
			  const struct nf_hook_state *state)
#else
unsigned int reflect_hook_ip4(unsigned int hooknum,
			  struct sk_buff *pskb,
			  const struct net_device *in,
			  const struct net_device *out,
			  int (*okfn)(struct sk_buff *))
#endif
{
	struct iphdr *inner_ip = NULL;
	struct tcphdr *tcp_header = NULL;
	struct icmphdr *icmp_header = NULL;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	u_int8_t tcp_state; /* From struct ip_ct_tcp */
	int inner_ip_len = 0;

	if (!pskb)
		goto accept;

	inner_ip = ip_hdr(pskb);
	inner_ip_len = htons(inner_ip->tot_len);

	if (!is_protocol_mark(pskb->mark, BDH_TCP))
		goto accept;
	if (VERBOSE >= LBM_INFO)
		pr_info("Received marked TCP pkt\n");

	if (inner_ip->protocol == IPPROTO_TCP)
		tcp_header = tcp_hdr(pskb);
	else if (inner_ip->protocol == IPPROTO_ICMP)
		icmp_header = icmp_hdr(pskb);
	else
		goto accept;

	if (icmp_header) {
		if (VERBOSE >= LBM_INFO)
			pr_info("ICMP packet\n");
	} else if (tcp_header == NULL ||
		(tcp_header->syn && !tcp_header->ack)) {
		/* Allow new SYN connections */
		if (VERBOSE >= LBM_INFO)
			pr_info("SYN packet found, accepting\n");
		goto accept;
	}

	ct = nf_ct_get(pskb, &ctinfo);

	// We explicity accept SYN packets so the only time we will see ctinfo
	// equal to IP_CT_NEW is when we receive a packet with ACK flag set but
	// we haven't seen the SYN packet for it. That should only happen for
	// packets that didn't have a connections established in this machine
	// ( packets that should be reflected ).
	if (ct == NULL || ctinfo == IP_CT_NEW) {
		if (VERBOSE >= LBM_INFO) {
			pr_info("Invalid conntrack, reflecting\n");
			pr_info("ct valid:%d ctinfo:%d\n",
				ct == NULL ? 0 : 1, (int)ctinfo);
		}
		goto reflect;
	}


	if (VERBOSE >= LBM_DEBUG) {
		pr_info("Original Src %X Dst %X Proto %d(%d) Sport %d Dport %d",
			ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
			ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip,
			ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.l3num,
			ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum,
			ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.tcp.port),
			ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port)
			);
		pr_info("Reply Src %X Dst %X Proto %d(%d) Sport %d Dport %d",
			ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip,
			ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip,
			ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.l3num,
			ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.protonum,
			ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.tcp.port),
			ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.tcp.port)
			);
		pr_info("Status %ld\n", ct->status);
	}
	tcp_state = (&ct->proto.tcp)->state;

	if (VERBOSE >= LBM_DEBUG) {
		pr_info("TCP State %d IP State %d\n", tcp_state,
			(int)ctinfo);
		if (tcp_state < sizeof(tcp_conntrack_names) &&
			(unsigned int)ctinfo < sizeof(ip_conntrack_names)) {
			pr_info("Pkt State { TCP: %s, IP: %s } ASSURED_BIT %d\n",
				tcp_conntrack_names[tcp_state],
				ip_conntrack_names[(int)ctinfo],
				test_bit(IPS_ASSURED_BIT, &ct->status));
		}
	}

	if (tcp_state == TCP_CONNTRACK_NONE) {
		if (VERBOSE >= LBM_INFO)
			pr_info("No connection, reflecting\n");
		goto reflect;
	} else if (tcp_state == TCP_CONNTRACK_ESTABLISHED &&
			!test_bit(IPS_ASSURED_BIT, &ct->status)) {
		if (VERBOSE >= LBM_INFO) {
			pr_info("Invalid ongoing connection, "
			"likely meant for another server, reflecting\n");
		}
		goto reflect;
	} else {
		goto accept;
	}

reflect:
	reflect_packet_ip4(pskb, inner_ip_len);

accept:
	return NF_ACCEPT;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
unsigned int snat_hook_ip4(void *priv,
		       struct sk_buff *pskb,
		       const struct nf_hook_state *state)
#else
unsigned int snat_hook_ip4(unsigned int hooknum,
		       struct sk_buff *pskb,
		       const struct net_device *in,
		       const struct net_device *out,
		       int (*okfn)(struct sk_buff *))
#endif
{
	struct iphdr *outer_ip = NULL;
	char *eth_ptr = NULL;
	__be32 temp_ip = 0;

	if (!is_protocol_mark(pskb->mark, BRH_SNAT)) {
		if (is_protocol_mark(pskb->mark, BRH_DECAP)) {
			/* If the driver has decap the pkt but it is not a pkt
			 * that should be daisy-chainned that means we
			 * terminated a pkt for a destination IP that is not in
			 * this server. We are not suppose to route it so drop
			 * it.
			 */
			if (VERBOSE >= LBM_WARN)
				pr_info("Pkt being routed that was decapped.\n");
			return NF_DROP;
		} else {
			return NF_ACCEPT;
		}
	}

	/* Extract the source ip from the inner eth header */
	eth_ptr = skb_mac_header(pskb);
	outer_ip = ip_hdr(pskb);
	memcpy(&temp_ip, eth_ptr, sizeof(__be32));
	if (temp_ip == 0) {
		if (VERBOSE >= LBM_WARN) {
			pr_info("Unable to get src ip from first 4 bytes of "
				"ethernet header, dropping pkt\n");
		}
		return NF_DROP;
	}
	if (VERBOSE >= LBM_INFO)
		pr_info("Mangle source ip to %pI4\n", &temp_ip);

	outer_ip->saddr = temp_ip;
	/* Recalculate checksum */
	pskb->ip_summed = CHECKSUM_NONE; /* Stop offloading */
	outer_ip->check = 0;
	outer_ip->check = ip_fast_csum((unsigned char *)outer_ip,
					outer_ip->ihl);

	/* Setting frag_max_size to zero to avoid fragmentation of this
	 * reflected packet
	 */
	IPCB(pskb)->frag_max_size = 0;
	return NF_ACCEPT;
}

