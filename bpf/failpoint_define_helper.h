// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#ifndef __FAILPOINT_DEFINE_HELPER_H
#define __FAILPOINT_DEFINE_HELPER_H

static __always_inline int handle_sys_entry_event(void *ctx, const char *name);
static __always_inline int handle_sys_exit_event(void *ctx, const char *name);

#define DEFINE_FAILPOINT(arch, sys_name) \
SEC("fentry.s+/"#arch#sys_name) \
int bpf_prog_fentry_##arch##sys_name(void *ctx) \
{ \
	return handle_sys_entry_event(ctx, #sys_name); \
} \
SEC("fexit.s+/"#arch#sys_name) \
int bpf_prog_fexit_##arch##sys_name(void *ctx) \
{ \
	return handle_sys_exit_event(ctx, #sys_name); \
}

#endif /* __FAILPOINT_DEFINE_HELPER_H */
