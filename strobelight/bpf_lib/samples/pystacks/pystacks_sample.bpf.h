// Copyright (c) Meta Platforms, Inc. and affiliates.

#ifndef __SAMPLE_PYSTACKS_BPF_H__
#define __SAMPLE_PYSTACKS_BPF_H__

#include <bpf/vmlinux/vmlinux.h> /* all kernel types */

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h> /* most used helpers: SEC, __always_inline, etc */
#include <bpf/bpf_tracing.h>

#include "strobelight/bpf_lib/common/common.h"
#include "strobelight/bpf_lib/samples/pystacks/structs.h"

extern struct event_heap_map {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct Event);
} event_heap SEC(".maps");

static inline struct Event* get_event(void) {
  return bpf_map_lookup_elem(&event_heap, &zero);
}

#endif // __BPF_HELPERS_H__
