//go:build ignore

#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <net/route.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"

#define IP_MF	  0x2000
#define IP_OFFSET 0x1FFF

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct event {
	__be32 src_addr;
	__be32 dst_addr;
	union {
//		__be32 ports;
		__be16 port16[2];
	};
	__u32 ip_proto;
	__u32 pkt_type;
	__u32 ifindex;

    unsigned char src_mac[6];
    unsigned char dst_mac[6];
    __u32 nexthop;
};
const struct event *unused __attribute__((unused));

static inline int ip_is_fragment(struct __sk_buff *skb, __u32 nhoff)
{
	__u16 frag_off;

	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, frag_off), &frag_off, 2);
	frag_off = __bpf_ntohs(frag_off);
	return frag_off & (IP_MF | IP_OFFSET);
}

SEC("socket")
int bpf_socket_handler(struct __sk_buff *skb)
{
	struct event *e;
	__u8 verlen;
	__u16 proto;
	__u32 nhoff = ETH_HLEN;

    unsigned long	_skb_refdst;

	bpf_skb_load_bytes(skb, 12, &proto, 2);
	proto = __bpf_ntohs(proto);
	if (proto != ETH_P_IP) /* Internet Protocol packet	*/
		return 0;

	if (ip_is_fragment(skb, nhoff))
		return 0;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

    // l2
    bpf_skb_load_bytes(skb, 0, &(e->dst_mac),6);
    bpf_skb_load_bytes(skb, 6, &(e->src_mac),6);

    // nexthop
    _skb_refdst = skb->_skb_refdst;
    struct dst_entry *dst = (struct dst_entry *)(_skb_refdst & SKB_DST_PTRMASK);
    struct rtable *rt = (struct rtable *)dst;
    e->nexthop = rt->rt_gateway;

	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, protocol), &e->ip_proto, 1);

	if (e->ip_proto != IPPROTO_GRE) {
		bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, saddr), &(e->src_addr), 4);
		bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, daddr), &(e->dst_addr), 4);
	}

	bpf_skb_load_bytes(skb, nhoff + 0, &verlen, 1);
//	bpf_skb_load_bytes(skb, nhoff + ((verlen & 0xF) << 2), &(e->ports), 4);
	bpf_skb_load_bytes(skb, nhoff + ((verlen & 0xF) << 2), &(e->port16), 4);
	e->pkt_type = skb->pkt_type;
	e->ifindex = skb->ifindex;
	bpf_ringbuf_submit(e, 0);

	return skb->len;
}
