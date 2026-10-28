/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
/* Defines xdp_stats_map from packet04 */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

/* Assignment 4 definitions */
#define VLAN_MAX_DEPTH 4

struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

static __always_inline int proto_is_vlan(__u16 h_proto)
{
        return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
                  h_proto == bpf_htons(ETH_P_8021AD));
}

/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in network byte order.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	/*
	 * Esta solución es correcta pero por lo que he entendido es más natural la segunda
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	/*
	 * Esto es más natural porque el compilador entiende que avanzar +1 en un puntero tipado
	 * (este caso: struct ethhdr) es avanzar el sizeof(*eth) (el tamaño del tipo de la variable a la que apunta)
	 */
	if (eth + 1 > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;

	/* Assignment 4 */ //Lo copie de la solución al final, esta es muy elegante.
	struct vlan_hdr *vlan = nh->pos;
	__u16 h_proto = eth->h_proto;

	#pragma unroll

	for(int i = 0; i < VLAN_MAX_DEPTH; i++)
	{
		if(!proto_is_vlan(h_proto))
			break;
		
		if(vlan + 1 > data_end)
			break;

		h_proto = vlan->h_vlan_encapsulated_proto;
		vlan++;
	}

	nh->pos = vlan;
	/* END Assignment 4 */

	return h_proto; /* network-byte-order */
}

/* Assignment 2: Implement and use this */
static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr * ipv6 = nh->pos;
	int hdrsize = sizeof(*ipv6);

	if(ipv6 + 1 > data_end)
		return -1;

	nh->pos += hdrsize;
	*ip6hdr = ipv6;

	//No se le hace ni hará bpf_ntohs o similares porque es solo un byte o menos.
	return ipv6->nexthdr;
}

/* Assignment 3: Implement and use this */
static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **icmp6hdr)	
{
	struct icmp6hdr * icmpv6 = nh->pos;
	int hdrsize = sizeof(*icmpv6);

	if(icmpv6 + 1 > data_end)
		return -1;

	nh->pos += hdrsize;
	*icmp6hdr = icmpv6;

	return bpf_ntohs(icmpv6->icmp6_sequence);
}

/* Assignment 5 */

static __always_inline int parse_ip4hdr(struct hdr_cursor *nh,
					void *data_end,
					struct iphdr **iphdr)
{
	struct iphdr * ipv4 = nh->pos;
	int hdrsize = sizeof(*ipv4);

	/* El tamaño de la cabecera IPv4 es dinámico, por lo que hay que hacer una comprobación en dos pasos*/

	// Paso 1: Tamaño estático de la struct.
	if(ipv4 + 1 > data_end)
		return -1;

	// Paso 2: cálculo según el número de words (bloques de 32 bits (4 bytes)) que pone en el campo de tamaño.
	hdrsize = ipv4->ihl * 4; //Num de words * tamaño de una word en bytes = num bytes.
	if(hdrsize < sizeof(*ipv4)) //Descartar que el ihl < 5 (Malformed package)
		return -1;

	if(nh->pos + hdrsize > data_end) //Comprobar que las opciones de verdad estén incluidas
	/* Se hace con nh porque el compilador intrtpreta que se sumen los bytes directamente, si lo hacemos
	 * con el puntero a struct iphdr, estaríamos sumando hdrsize veces el sizeof(struct iphdr).
	 * Otra opción es hacerle un cast a void *, pero para eso usamos nh->pos.
	 */
		return -1;

	nh->pos += hdrsize;
	*iphdr = ipv4;

	//No se le hace ni hará bpf_ntohs o similares porque es solo un byte o menos.
	return ipv4->protocol;
}

static __always_inline int parse_icmp4hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmphdr **icmphdr)	
{
	struct icmphdr * icmpv4 = nh->pos;
	int hdrsize = sizeof(*icmpv4);

	if(icmpv4 + 1 > data_end)
		return -1;

	nh->pos += hdrsize;
	*icmphdr = icmpv4;

	return bpf_ntohs(icmpv4->un.echo.sequence);
}

SEC("xdp")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;
	struct iphdr *ip;
	struct icmphdr *icmp;
	struct ipv6hdr *ipv6;
	struct icmp6hdr *icmp6;
	int sequence = -1;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth);



	switch(nh_type)
	{
		/* Assignment 5 */
		case bpf_htons(ETH_P_IP):
			nh_type = parse_ip4hdr(&nh, data_end, &ip);
			if (nh_type != IPPROTO_ICMP)
				goto out;

			sequence = parse_icmp4hdr(&nh, data_end, &icmp);
			if(sequence == -1)
			{
				action = XDP_ABORTED;
				goto out;
			}
			if (sequence % 2 != 0)
				goto out;

			action = XDP_DROP;
			
			break;

		case bpf_htons(ETH_P_IPV6):
			/* Assignment additions go below here */
			nh_type = parse_ip6hdr(&nh, data_end, &ipv6);
			//No se le hace ni hará bpf_ntohs o similares porque es solo un byte o menos.
			if (nh_type != IPPROTO_ICMPV6)
				goto out;

			sequence = parse_icmp6hdr(&nh, data_end, &icmp6);
			if(sequence == -1)
			{
				action = XDP_ABORTED;
				goto out;
			}
			if (sequence % 2 != 0)
				goto out;

			action = XDP_DROP;

			break;

		default:
			goto out;
	}

out:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
