#include <string.h>
#include <poll.h>
#include <perf-sys.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define CPUS	4

struct packet {
	unsigned int src;
	unsigned int dst;
	unsigned short l3proto;
	unsigned short l4proto;
	unsigned short sport;
	unsigned short dport;
};

struct perf_event_data {
	struct perf_event_header header;
	unsigned long long ts;
	unsigned int size;
	struct packet p;
};

static enum bpf_perf_event_ret print_packet(struct perf_event_header *hdr, void *fn)
{
	struct perf_event_data *data = (struct perf_event_data *)hdr;
	struct packet p = data->p;
	unsigned long long ts = data->ts;
	char src[16], dst[16];
	char l3proto[8], l4proto[8];
	unsigned short sport = 0, dport = 0;

	// 直接打印数据包协议元数据，正常应该是利用libpcap接口来处理的。
	switch (p.l3proto) {
	case ETH_P_IP:
		strcpy(l3proto, "IP");
		inet_ntop(AF_INET, &p.src, src, 16);
		inet_ntop(AF_INET, &p.dst, dst, 16);
		break;
	default:
		sprintf(l3proto, "%04x", p.l3proto);
	}

	switch (p.l4proto) {
	case IPPROTO_TCP:
		strcpy(l4proto, "TCP");
		sport = ntohs(p.sport);
		dport = ntohs(p.dport);
		break;
	case IPPROTO_UDP:
		strcpy(l4proto, "UDP");
		sport = ntohs(p.sport);
		dport = ntohs(p.dport);
		break;
	case IPPROTO_ICMP:
		strcpy(l4proto, "ICMP");
		break;
	default:
		strcpy(l4proto, "Unknown");
	}

	printf("%lld.%06lld %s:%d > %s:%d > %s %s\n", ts/1000000000, (ts%1000000000)/1000, src, sport, dst, dport, l3proto, l4proto);
	return LIBBPF_PERF_EVENT_CONT;
}

int main(int argc, char **argv)
{
	static struct perf_event_mmap_page *buffer[CPUS];
	int eventmap_fd, he;
	int perf_fds[CPUS];
	void *tmp = NULL;
	unsigned long len = 0;
	int i;
	struct pollfd fds[CPUS];
	struct perf_event_attr attr = {
		.sample_type	= PERF_SAMPLE_RAW | PERF_SAMPLE_TIME,
		.type		= PERF_TYPE_SOFTWARE,
		.config		= PERF_COUNT_SW_BPF_OUTPUT,
		.wakeup_events	= 1,
	};

	eventmap_fd = bpf_obj_get(argv[1]);

	for (i = 0; i < CPUS; i++) {
		he = sys_perf_event_open(&attr, -1, i, -1, 0);
		ioctl(he, PERF_EVENT_IOC_ENABLE, 0);
		buffer[i] = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, he, 0);
		bpf_map_update_elem(eventmap_fd, &i, &he, BPF_ANY);
		perf_fds[i] = he;
	}

	for (i = 0; i < CPUS; i++) {
		fds[i].fd = perf_fds[i];
		fds[i].events = POLLIN;
	}

	while (1) {
		poll(fds, CPUS, 0);
		for (i = 0; i < CPUS; i++)
			bpf_perf_event_read_simple(buffer[i], 8192, 4096, &tmp, &len, print_packet, NULL);
	}
	return 0;
}

