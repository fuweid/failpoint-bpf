// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "failpoint_define_helper.h"
#include "failpoint_define.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

volatile pid_t filter_pid = 0;

static __always_inline int handle_sys_entry_event(void *ctx, const char *name, u32 sys_id)
{
	u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;

	if (filter_pid && pid != filter_pid)
		return 0;

	bpf_printk("fentry %s\n", name);
	return 0;
}

static __always_inline int handle_sys_exit_event(void *ctx, const char *name, u32 sys_id) {
	u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;

	if (filter_pid && pid != filter_pid)
		return 0;

	bpf_printk("fexit %s\n", name);
	return 0;
}

SEC("raw_tracepoint/sched_process_exit")
int handle_sched_process_exit(void* ctx) {
	u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;
	u32 tid = (u32)id;

	if (filter_pid && pid != filter_pid)
		return 0;

	if (pid != tid)
		return 0;

	// NOTE: disable failpoint if process exit
	filter_pid = 0;
	return 0;
}
