// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// filter_pid is the target process id. It's been updated by bpf loader or
// sched_process_exit tracing prog.
volatile pid_t filter_pid = 0;

// zero_value is used with bpf_map_lookup_or_init if the record is not exist.
const u64 zero_value = 0;

// bpf_failpoint_delay is alias symbol to kernel msleep. It's required module
// to register the kfunc before using it.
extern void bpf_failpoint_delay(unsigned int msecs) __ksym;

// when_expr follows strace(1) convention to define expression for injecting
// failpoint to target syscalls.
//
// The format of the subexpression is: first[..last][+[step]].
//
// REF: https://man7.org/linux/man-pages/man1/strace.1.html
struct when_expr {
	__u32 first;
	__u32 last;
	__u32 step;
};

// failpoint_spec is the specification to allow bpf prog to perform injection on
// the target syscall.
struct failpoint_spec {
	struct when_expr when;
	// delay_enter_msecs is the duration used to delay on entering the syscall.
	__u32 delay_enter_msecs;
	// delay_exit_msecs is the duration used to delay on exiting the syscall.
	__u32 delay_exit_msecs;
};

// sys_failpoints is the collection of failpoint specifications.
//
// The key is the address of syscall handler.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, __u64);
	__type(value, struct failpoint_spec);
} sys_failpoints SEC(".maps");

// sys_entry_counts is stats about counts for entering syscall.
//
// The key is the address of syscall handler.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, __u64);
	__type(value, __u64);
} sys_entry_counts SEC(".maps");

// sys_exit_counts is stats about counts for exiting syscall.
//
// The key is the address of syscall handler.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, __u64);
	__type(value, __u64);
} sys_exit_counts SEC(".maps");

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

static bool should_inject(struct when_expr *when, u32 count);
static void *bpf_map_lookup_or_init(void *map, const void *key, const void *init_val);

SEC("fentry.s+/unknown")
static int handle_sys_entry_event(void *ctx)
{
	struct failpoint_spec *fp;
	u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;
	u64 *cnt;
	u64 current_cnt = 0;
	u64 target_addr = bpf_get_func_ip(ctx);

	if (filter_pid && pid != filter_pid)
		return 0;

	cnt = bpf_map_lookup_or_init(&sys_entry_counts, &target_addr, &zero_value);
	if (!cnt) {
		return 0;
	}
	current_cnt = __sync_add_and_fetch(cnt, 1);

	fp = (struct failpoint_spec *)bpf_map_lookup_elem(&sys_failpoints, &target_addr);
	if (!fp)
		return 0;

	if (should_inject(&fp->when, current_cnt) && fp->delay_enter_msecs != 0) {
		bpf_printk("fentry %x %d\n", target_addr, fp->delay_enter_msecs);
		bpf_failpoint_delay(fp->delay_enter_msecs);
	}
	return 0;
}

SEC("fexit.s+/unknown")
static int handle_sys_exit_event(void *ctx)
{
	struct failpoint_spec *fp;
	u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;
	u64 *cnt;
	u64 current_cnt = 0;
	u64 target_addr = bpf_get_func_ip(ctx);

	if (filter_pid && pid != filter_pid)
		return 0;

	cnt = bpf_map_lookup_or_init(&sys_exit_counts, &target_addr, &zero_value);
	if (!cnt) {
		return 0;
	}
	current_cnt = __sync_add_and_fetch(cnt, 1);

	fp = (struct failpoint_spec *)bpf_map_lookup_elem(&sys_failpoints, &target_addr);
	if (!fp)
		return 0;

	if (should_inject(&fp->when, current_cnt) && fp->delay_exit_msecs != 0) {
		bpf_printk("fexit %x %d\n", target_addr, fp->delay_exit_msecs);
		bpf_failpoint_delay(fp->delay_exit_msecs);
	}
	return 0;
}

// bpf_map_lookup_or_init will create recording with a given init values if
// there is no such record.
static void *bpf_map_lookup_or_init(void *map, const void *key, const void *init_val)
{
        void *val = bpf_map_lookup_elem(map, key);
        if (val)
                return val;

        int err = bpf_map_update_elem(map, key, init_val, BPF_NOEXIST);
        if (err && err != -EEXIST)
                return 0;

        return bpf_map_lookup_elem(map, key);
}

// should_inject returns true if it matches when expression.
static bool should_inject(struct when_expr *when, u32 count)
{
	if (!when)
		return false;

	if (!when->first)
		return true;

	if (when->first > count)
		return false;

	if (when->last && when->last < count)
		return false;

	u32 diff = count - when->first;
	return !when->step || ((diff % when->step) == 0);
}
