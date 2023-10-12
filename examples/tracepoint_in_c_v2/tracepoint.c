//go:build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// This struct is defined according to the following format file:
// /sys/kernel/tracing/events/sched/sched_process_exec/format
#define MAX_FILENAME_LEN 512
struct event {
	u32 pid;
	u8 comm[80];
	u8 filename[MAX_FILENAME_LEN];
};
const struct event *unused __attribute__((unused));

struct trace_entry {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};

/* sched_process_exec tracepoint context */
struct trace_event_raw_sched_process_exec {
	struct trace_entry ent;
	unsigned int __data_loc_filename;
	int pid;
	int old_pid;
	char __data[0];
};

/* BPF ringbuf map */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} events SEC(".maps");

// This tracepoint is defined in mm/page_alloc.c:__alloc_pages_nodemask()
// Userspace pathname: /sys/kernel/tracing/events/sched/sched_process_exec
SEC("tracepoint/sched/sched_process_exec")
int sched_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
	unsigned fname_off = ctx->__data_loc_filename & 0xFFFF;
	struct event *e;
	int zero = 0;

	e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!e) {
		return 0;
	}

	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
