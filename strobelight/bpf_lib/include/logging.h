// Copyright (c) Meta Platforms, Inc. and affiliates.

#ifndef __BPF_LIB_LOGGING_H
#define __BPF_LIB_LOGGING_H

extern "C" {

enum strobelight_lib_print_level {
  STROBELIGHT_LIB_WARN,
  STROBELIGHT_LIB_INFO,
  STROBELIGHT_LIB_DEBUG,
};

typedef int (*strobelight_lib_print_fn_t)(
    enum strobelight_lib_print_level level,
    const char*);

/**
 * @brief **strobelight_lib_set_print()** sets user-provided log callback
 * function to be used for strobelight-lib warnings and informational messages.
 * If the user callback is not set, messages are not logged.
 * @param fn The log print function. NULL by default and does not print
 * anything.
 * @return Pointer to old print function.
 *
 * This function is thread-safe.
 */
strobelight_lib_print_fn_t strobelight_lib_set_print(
    strobelight_lib_print_fn_t fn);
}

#endif /* __BPF_LIB_LOGGING_H */
