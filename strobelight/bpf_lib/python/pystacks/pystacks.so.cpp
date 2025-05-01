// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "strobelight/bpf_lib/python/pystacks/pystacks.so.h"
#include "strobelight/bpf_lib/python/pystacks/pystacks.h"

extern "C" {

int load_stack_walker(struct stack_walker* pystacks) {
  if (nullptr == pystacks) {
    return 1;
  }
  pystacks->init = pystacks_init;
  pystacks->free = pystacks_free;
  pystacks->symbolize_function = pystacks_symbolize_function;
  pystacks->symbolize_filename_line = pystacks_symbolize_filename_line;

  return 0;
}

} // extern "C"
