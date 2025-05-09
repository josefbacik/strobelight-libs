// Copyright (c) Meta Platforms, Inc. and affiliates.

#ifndef __BPF_LIB_PTHREAD_HELPERS_H__
#define __BPF_LIB_PTHREAD_HELPERS_H__

// @oss-disable: #include <bpf/vmlinux/vmlinux.h>
#include <vmlinux.h> // @oss-enable

int probe_read_pthread_tls_slot(
    uint32_t key,
    void** value,
    struct task_struct* task);

#endif // __BPF_LIB_PTHREAD_HELPERS_H__
