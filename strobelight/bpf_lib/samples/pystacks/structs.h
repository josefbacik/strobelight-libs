// Copyright (c) Meta Platforms, Inc. and affiliates.

#ifndef __SAMPLE_PYSTACKS_STRUCTS_H__
#define __SAMPLE_PYSTACKS_STRUCTS_H__

#ifdef __cplusplus
#include <bpf/uapi/linux/bpf.h>
#endif

#include "strobelight/bpf_lib/python/include/structs.h"

#define TASK_COMM_LENGTH 16

// max size of this programs data plus max size of libraries data
#define EVENT_BUFFER_SIZE (512 + 4096)

struct Event {
  size_t buff_size;
  pid_t pid;
  pid_t tid;
  char comm[TASK_COMM_LENGTH];
  uint64_t ktime;

  struct pystacks_message py_msg_buffer;
};

#endif
