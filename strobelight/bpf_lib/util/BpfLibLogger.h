// Copyright (c) Meta Platforms, Inc. and affiliates.

#ifndef __BPF_LIB_LOGGER_H
#define __BPF_LIB_LOGGER_H

#include "strobelight/bpf_lib/include/logging.h"

extern "C" {
#include <bpf/libbpf.h>
}

void strobelight_lib_print(
    enum strobelight_lib_print_level level,
    const char* msg);

#endif /* __BPF_LIB_LOGGER_H */
