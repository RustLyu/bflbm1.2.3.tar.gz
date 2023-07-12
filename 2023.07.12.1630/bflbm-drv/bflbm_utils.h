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
 * Copyright (c) 2020 Arista Networks, Inc.  All rights reserved.
 */

#ifndef PACKET_UTILS_H
#define PACKET_UTILS_H

#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/types.h>
#include <linux/version.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/vxlan.h>

/* Structs */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
struct __attribute__((__packed__)) outer_packet_ip4
{
	struct iphdr ip_header;
	struct udphdr udp_header;
	struct vxlanhdr vxlan_header;
};

struct __attribute__((__packed__)) outer_packet_ip6
{
	struct ipv6hdr ip_header;
	struct udphdr udp_header;
	struct vxlanhdr vxlan_header;
};

#else
struct __attribute__((__packed__)) outer_packet_ip4
{
	struct iphdr ip_header;
	struct udphdr udp_header;
	struct vxlanhdr {
		__be32 vx_flags;
		__be32 vx_vni;
	} vxlan_header;
};
struct __attribute__((__packed__)) outer_packet_ip6
{
	struct ipv6hdr ip_header;
	struct udphdr udp_header;
	struct vxlanhdr {
		__be32 vx_flags;
		__be32 vx_vni;
	} vxlan_header;
};

#define VLAN_ETH_HLEN	18
#endif

struct __attribute((__packed__))inner_packet_ip4 {
	struct iphdr ip_header;
	struct tcphdr tcp_header;
};

struct __attribute((__packed__)) inner_packet_ip6 {
	struct ipv6hdr ip_header;
	struct tcphdr tcp_header;
};

/* From enum tcp_conntrack
 * in /include/uapi/linux/netfilter/nf_conntrack_tcp.h
 * used only for debug printing purposes
 */
static const char *const tcp_conntrack_names[] = {
	"NONE",
	"SYN_SENT",
	"SYN_RECV",
	"ESTABLISHED",
	"FIN_WAIT",
	"CLOSE_WAIT",
	"LAST_ACK",
	"TIME_WAIT",
	"CLOSE",
	"SYN_SENT2",
};

/* From enum ip_conntrack_info
 * in /include/uapi/linux/netfilter/nf_conntrack_common.h
 * used only for debug printing purposes
 */
static const char *const ip_conntrack_names[] = {
	"ESTABLISHED",
	"RELATED",
	"NEW",
};

static inline void clear_protocol_mark(struct sk_buff *skb)
{
	/* Clear the 3 bits used */
	skb->mark &= ~(7 << MARK_OFFSET);
}

static inline void set_protocol_mark(struct sk_buff *skb, uint32_t protocol)
{
	skb->mark |= (protocol << MARK_OFFSET);
}

static inline uint32_t is_protocol_mark(uint32_t mark, uint32_t protocol)
{
	return ((mark & (protocol << MARK_OFFSET))  > 0);
}

static int find_inner_offset(unsigned char *data_ptr)
{
	int inner_offset = ETH_HLEN;
	struct ethhdr *eth  = (struct ethhdr *)data_ptr;

	/* Potential vlan header */
	if (eth->h_proto == htons(ETH_P_8021Q) ||
	    eth->h_proto == htons(ETH_P_8021AD)) {
		inner_offset = VLAN_ETH_HLEN;
	}
	return inner_offset;
}

static inline void printk_ip4(struct iphdr *ip)
{
	pr_info("\tIP HEADER: Version %u, Protocol %u, Src %pI4, Dest %pI4\n",
		ip->version,
		ip->protocol,
		&(ip->saddr),
		&(ip->daddr));
}

static inline void printk_ip6(struct ipv6hdr *ip)
{
	pr_info("\tIP HEADER: Version %u, Protocol %u, Src %pI6, Dest %pI6\n",
		ip->version,
		ip->nexthdr,
		&(ip->saddr),
		&(ip->daddr));
}

static inline void printk_outer_packet_ip4(struct outer_packet_ip4 *opkt)
{
	printk_ip4(&(opkt->ip_header));
	pr_info("\tUDP HEADER: Src Port %i, Dest Port %i, Check 0x%X\n",
		ntohs(opkt->udp_header.source),
		ntohs(opkt->udp_header.dest),
		opkt->udp_header.check);

	pr_info("\tVXLAN HEADER: Flags %x, VNI %i\n",
		opkt->vxlan_header.vx_flags,
		ntohl(opkt->vxlan_header.vx_vni) >> 8);
}

static inline void printk_outer_packet_ip6(struct outer_packet_ip6 *opkt)
{
	printk_ip6(&(opkt->ip_header));
	pr_info("\tUDP HEADER: Src Port %i, Dest Port %i, Check 0x%X\n",
		ntohs(opkt->udp_header.source),
		ntohs(opkt->udp_header.dest),
		opkt->udp_header.check);

	pr_info("\tVXLAN HEADER: Flags %x, VNI %i\n",
		opkt->vxlan_header.vx_flags,
		ntohl(opkt->vxlan_header.vx_vni) >> 8);
}

static inline void printk_inner_packet_ip4(struct inner_packet_ip4 *ipkt)
{
	printk_ip4(&(ipkt->ip_header));
	/* Check if ip header has options, if so, tcp hdr will be misaligned */
	if (ipkt->ip_header.protocol == IPPROTO_TCP &&
		ipkt->ip_header.ihl * 4 <= sizeof(struct iphdr)) {
		pr_info("\tTCP HEADER: Src Port %i, Dest Port %i\n",
			ntohs(ipkt->tcp_header.source),
			ntohs(ipkt->tcp_header.dest));
	}
}

static inline void printk_inner_packet_ip6(struct inner_packet_ip6 *ipkt)
{
	printk_ip6(&(ipkt->ip_header));
	if (ipkt->ip_header.nexthdr == IPPROTO_TCP) {
		pr_info("\tTCP HEADER: Src Port %i, Dest Port %i\n",
			ntohs(ipkt->tcp_header.source),
			ntohs(ipkt->tcp_header.dest));
	}
}
#endif // PACKET_UTILS_H

