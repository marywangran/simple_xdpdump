#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include "bpf_helpers.h"

SEC("xdp_echo")
int xdp_echo_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	int in_index = ctx->ingress_ifindex;
	char info_fmt[] = "echo to %d \n";

	if (data + sizeof(struct ethhdr) > data_end) {
		return XDP_DROP;
	}

	bpf_trace_printk(info_fmt, sizeof(info_fmt), in_index);
	return  bpf_redirect(in_index, 0);
}

char _license[] SEC("license") = "GPL";

