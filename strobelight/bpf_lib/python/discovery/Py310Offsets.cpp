// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "strobelight/bpf_lib/python/include/OffsetConfig.h"

namespace facebook::strobelight::bpf_lib {

// clang-format off
//
// $ gdb --batch --command=./scripts/pyperf.gdb --args /usr/local/fbcode/platform010/lib/libpython3.10.so
//
// clang-format on

extern const OffsetConfig kPy310OffsetConfig = [] {
  OffsetConfig config;
  config.PyObject_type = 8;
  config.PyTypeObject_name = 24;
  config.PyThreadState_frame = 24;
  config.PyThreadState_thread = 176;
  config.PyThreadState_interp = 16;
  config.PyInterpreterState_modules = 856;
  config.PyFrameObject_back = 24;
  config.PyFrameObject_code = 32;
  config.PyFrameObject_lasti = 96;
  config.PyFrameObject_localsplus = 352;
  config.PyFrameObject_gen = 88;
  config.PyCodeObject_co_flags = 36;
  config.PyCodeObject_filename = 104;
  config.PyCodeObject_name = 112;
  config.PyCodeObject_varnames = 72;
  config.PyCodeObject_firstlineno = 40;
  config.PyCodeObject_linetable = 120;
  config.PyTupleObject_item = 24;
  config.String_data = 48;
  config.TLSKey_offset = 588;
  config.TCurrentState_offset = 568;
  config.PyGIL_offset = 368;
  config.PyGIL_last_holder = 360;
  config.PyBytesObject_data = 32;
  config.PyVarObject_size = 16;
  config.PyVersion_major = 3;
  config.PyVersion_minor = 10;
  config.PyVersion_micro = 0;
  return config;
}();

} // namespace facebook::strobelight::bpf_lib
