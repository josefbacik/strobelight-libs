// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "strobelight/bpf_lib/util/BpfLibLogger.h"
#include <errno.h>
#include "strobelight/bpf_lib/include/logging.h"

static strobelight_lib_print_fn_t __strobelight_lib_printer = nullptr;

strobelight_lib_print_fn_t strobelight_lib_set_print(
    strobelight_lib_print_fn_t fn) {
  strobelight_lib_print_fn_t old_print_fn;

  old_print_fn =
      __atomic_exchange_n(&__strobelight_lib_printer, fn, __ATOMIC_RELAXED);

  return old_print_fn;
}

void strobelight_lib_print(
    enum strobelight_lib_print_level level,
    const char* msg) {
  int old_errno;
  strobelight_lib_print_fn_t print_fn;

  print_fn = __atomic_load_n(&__strobelight_lib_printer, __ATOMIC_RELAXED);
  if (!print_fn) {
    return;
  }

  old_errno = errno;

  print_fn(level, msg);

  errno = old_errno;
}
