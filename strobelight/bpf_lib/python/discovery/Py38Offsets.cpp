// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "strobelight/bpf_lib/python/include/OffsetConfig.h"

namespace facebook::strobelight::bpf_lib {

// clang-format off
//
// platform009
// -----------
// $ gdb --batch --command=./scripts/pyperf.gdb --args /usr/local/fbcode/platform009/lib/libpython3.8.so
//
// platform010
// -----------
// $ gdb --batch --command=./scripts/pyperf.gdb --args /usr/local/fbcode/platform010/lib/libpython3.8.so
//
// NOTE: platform009 and platform010 python3.8 offset configs are identical
// clang-format on

extern const OffsetConfig kPy38OffsetConfig = [] {
  OffsetConfig config;
  config.PyObject_type = 8;
  config.PyTypeObject_name = 24;
  config.PyThreadState_frame = 24;
  config.PyThreadState_thread = 176;
  config.PyFrameObject_back = 24;
  config.PyFrameObject_code = 32;
  config.PyFrameObject_localsplus = 360;
  config.PyFrameObject_gen = 96;
  config.PyCodeObject_co_flags = 36;
  config.PyCodeObject_filename = 104;
  config.PyCodeObject_name = 112;
  config.PyCodeObject_varnames = 72;
  config.PyTupleObject_item = 24;
  config.String_data = 48;
  config.TLSKey_offset = 1396;
  config.TCurrentState_offset = 1368;
  config.PyGIL_offset = 1168;
  config.PyGIL_last_holder = 1160;
  config.PyVersion_major = 3;
  config.PyVersion_minor = 8;
  config.PyVersion_micro = 0;
  return config;
}();

} // namespace facebook::strobelight::bpf_lib
