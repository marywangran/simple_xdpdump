#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"

struct bpf_elf_map {
	__u32 type;
	__u32 size_key;
	__u32 size_value;
	__u32 max_elem;
	__u32 flags;
	__u32 id;
	__u32 pinning;
};

#define PIN_GLOBAL_NS		2

// 保存下一个eBPF程序，即本文中的test_echo程序，提供给尾调用。
struct bpf_elf_map SEC("maps") next_prog_map = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.size_key = sizeof(u32),
	.size_value = sizeof(u32),
	.pinning        = PIN_GLOBAL_NS,
	.max_elem = 1,
};

// 保存抓取的数据包体，这仅仅用协议元组数据来模拟。
struct packet {
	unsigned int src;
	unsigned int dst;
	unsigned short l3proto;
	unsigned short l4proto;
	unsigned short sport;
	unsigned short dport;
};

// 保存抓取数据包事件信息
struct bpf_elf_map SEC("maps") event_map = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.size_key = sizeof(u32),
	.size_value = sizeof(u32),
	.pinning        = PIN_GLOBAL_NS,
	.max_elem = 128,
};

SEC("xdp_dump")
int xdp_dump_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct packet p = {};

	if (data + sizeof(struct ethhdr) > data_end) {
		return XDP_DROP;
	}

	p.l3proto = bpf_htons(eth->h_proto);
	if (p.l3proto == ETH_P_IP) {
		struct iphdr *iph;

		iph = data + sizeof(struct ethhdr);
		if (iph + 1 > data_end)
			return XDP_DROP;

		p.src = iph->saddr;
		p.dst = iph->daddr;
		p.l4proto = iph->protocol;
		p.sport = p.dport = 0;
		if (iph->protocol == IPPROTO_TCP) {
			struct tcphdr *tcph;
			tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
			if (tcph + 1 > data_end)
				return XDP_DROP;

			p.sport = tcph->source;
			p.dport = tcph->dest;
		} else if (iph->protocol == IPPROTO_UDP) {
			struct udphdr *udph;
			udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
			if (udph + 1 > data_end)
				return XDP_DROP;

			p.sport = udph->source;
			p.dport = udph->dest;
		}
		// 事件上报给xdpdump抓包进程
		bpf_perf_event_output(ctx, &event_map, BPF_F_CURRENT_CPU, &p, sizeof(p));
	}

	// 尾调用，调用正常的test_echo eBPF程序
	bpf_tail_call(ctx, &next_prog_map, 0);

	// 如果没有attach别的eBPF程序，则直接PASS
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

