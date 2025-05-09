// Copyright (c) Meta Platforms, Inc. and affiliates.

#ifndef __STROBELIGHT_BPF_LIB_COMMON_H__
#define __STROBELIGHT_BPF_LIB_COMMON_H__

#ifndef __cplusplus
// @oss-disable: #include <bpf/vmlinux/vmlinux.h>
#include <vmlinux.h> // @oss-enable
#else
// @oss-disable: #include <bpf/uapi/linux/bpf.h>
#include <linux/bpf.h> // @oss-enable
#include <ostream>
#endif

// from <linux/sched.h>
#define PF_IDLE 0x00000002 /* I am an IDLE thread */
#define PF_KTHREAD 0x00200000 /* I am a kernel thread */

#define MIN_USER_SPACE_ADDRESS ((uintptr_t)0x1000)
#ifdef __x86_64__
// https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
#define MAX_USER_SPACE_ADDRESS ((uintptr_t)0x00ffffffffffffff)
#elif defined(__aarch64__)
// https://www.kernel.org/doc/Documentation/arm64/memory.txt
#define MAX_USER_SPACE_ADDRESS ((uintptr_t)0x0000007fffffffff)
#else
#error Unsupported architecture
#endif

#define IS_VALID_USER_SPACE_ADDRESS(addr)         \
  (((uintptr_t)addr) >= MIN_USER_SPACE_ADDRESS && \
   ((uintptr_t)addr) <= MAX_USER_SPACE_ADDRESS)

extern int32_t zero;

#endif // __STROBELIGHT_BPF_LIB_COMMON_H__
