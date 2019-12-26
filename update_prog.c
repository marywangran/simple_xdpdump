#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include "bpf_util.h"

static int progmap_fd;

int main(int argc, char **argv)
{
	int idx = 0;
	int opt = 1;
	char *mapfile;
	struct bpf_object *obj;
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_XDP,
	};
	int prog_fd;

	opt = atoi(argv[1]);
	mapfile = argv[2]; // 获取全局可见的PIN map文件位置
	prog_load_attr.file = argv[3];
	progmap_fd = bpf_obj_get(mapfile);
	if (opt == 0) {
		bpf_map_delete_elem(progmap_fd, &idx);
		return 0;
	}

	// 载入eBPF程序
	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd)) {
		return 1;
	}

	bpf_map_update_elem(progmap_fd, &idx, &prog_fd, 0);
	return 0;
}

