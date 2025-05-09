// Copyright (c) Meta Platforms, Inc. and affiliates.

#ifndef __BPF_LIB_NAMESPACE_HELPERS_H__
#define __BPF_LIB_NAMESPACE_HELPERS_H__

#ifndef __cplusplus
// @oss-disable: #include <bpf/vmlinux/vmlinux.h>
#include <vmlinux.h> // @oss-enable
#else
// @oss-disable: #include <bpf/uapi/linux/bpf.h>
#include <linux/bpf.h> // @oss-enable
#include <ostream>
#endif

struct pid_namespace* get_task_pid_ns(const struct task_struct* task);
pid_t get_task_ns_pid(const struct task_struct* task);

pid_t get_pid_nr_ns(struct pid* pid, struct pid_namespace* ns);
pid_t get_ns_pid(void);

#endif // __BPF_LIB_NAMESPACE_HELPERS_H__
