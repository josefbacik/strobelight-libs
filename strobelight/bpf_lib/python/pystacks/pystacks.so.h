// Copyright (c) Meta Platforms, Inc. and affiliates.

#ifndef __BPF_LIB_PYSTACKS_SO_H__
#define __BPF_LIB_PYSTACKS_SO_H__

#include "strobelight/bpf_lib/include/stack_walker.h"

#ifdef __cplusplus
extern "C" {
#endif

int load_stack_walker(struct stack_walker*);

#ifdef __cplusplus
} // extern "C"
#endif

#endif
