// Copyright (c) Meta Platforms, Inc. and affiliates.

#ifndef __BPF_LIB_NETWORK_HELPERS_H__
#define __BPF_LIB_NETWORK_HELPERS_H__

#include <errno.h>
#include <linux/bpf.h>

__always_inline long read_tcp_header(
    const void* data,
    __u32 offset,
    const void* data_end,
    struct tcphdr** tcphdr) {
  struct tcphdr* th = (struct tcphdr*)(data + offset);
  if (th + 1 > data_end)
    return -EINVAL;

  *tcphdr = th;
  return 0;
}

#endif // __BPF_LIB_NETWORK_HELPERS_H__
