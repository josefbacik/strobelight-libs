// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "strobelight/bpf_lib/python/include/OffsetConfig.h"

namespace facebook::strobelight::bpf_lib {

// clang-format off
//
// $ buck2 run @//mode/opt -c python.force_py_version=3.12 //strobelight/tools/pyperf:pyperf_test_cpython
// ...
// Running as process pid 1446049
// Running forever
//
// $ lldb -p <pid>
// (lldb) command script import ~/fbsource/fbcode/strobelight/scripts/pyperf_lldb.py
// (lldb) dump_py_offsets
//
// clang-format on

/*
Items that no longer exist in 3.12
- PyThreadState_frame, replaced by PyThreadState_cframe, and
_PyCFrame_current_frame
- PyFrameObject_back (exists but stack walking is done using the
InterpreterFrame)
- PyFrameObject_code, replaced by PyInterpreterFrame_code
- PyFrameObject_lasti, replaced by PyInterpreterFrame_prev_instr,
https://fburl.com/75evvudp
- PyFrameObject_localsplus, replaced by PyInterpreterFrame_localsplus

Deprecated offsets:
- PyFrameObject_gen, replaced by runtime function _PyFrame_GetGenerator().
- PyCodeObject_varnames
- PyGIL_offset (T186091105 to remove)
- PyGIL_last_holder (T186091105 to remove)
*/

extern const OffsetConfig kPy312OffsetConfig = [] {
  OffsetConfig config;
  config.PyObject_type = 8; // offsetof(PyObject, ob_type)
  config.PyTypeObject_name = 24; // offsetof(PyTypeObject, tp_name)

  // cframe wraps around frame
  config.PyThreadState_cframe = 56; // offsetof(PyThreadState, cframe)
  config.PyThreadState_thread = 136; // offsetof(PyThreadState, thread_id)
  config.PyThreadState_interp = 16; // offsetof(PyThreadState, interp)
  config.PyInterpreterState_modules =
      944; // offsetof(PyInterpreterState, modules)

  // replaces frame
  config._PyCFrame_current_frame = 0; // offsetof(_PyCFrame, current_frame)

  // replaces PyFrameObject_code
  config.PyInterpreterFrame_code = 0; // offsetof(_PyInterpreterFrame, f_code)

  // replaces PyFrameObject_cback
  config.PyInterpreterFrame_previous =
      8; // offsetof(_PyInterpreterFrame, previous)
  config.PyInterpreterFrame_localsplus =
      72; // offsetof(_PyInterpreterFrame, localsplus)
  config.PyInterpreterFrame_prev_instr =
      56; // offsetof(_PyInterpreterFrame, prev_instr)
  config.PyCodeObject_co_flags = 48; // offsetof(PyCodeObject, co_flags)
  config.PyCodeObject_filename = 112; // offsetof(PyCodeObject, co_filename)
  config.PyCodeObject_name = 120; // offsetof(PyCodeObject, co_name)
  config.PyCodeObject_qualname = 128; // offsetof(PyCodeObject, co_qualname)
  config.PyCodeObject_linetable = 136; // offsetof(PyCodeObject, co_linetable)
  config.PyCodeObject_firstlineno =
      68; // offsetof(PyCodeObject, co_firstlineno)
  config.PyCodeObject_code_adaptive =
      192; // offsetof(PyCodeObject, co_code_adaptive)
  config.PyTupleObject_item = 24; // offsetof(PyTupleObject, ob_item)
  config.TLSKey_offset = 1548; // offsetof(_PyRuntimeState, autoTSSkey._key)
  config.PyBytesObject_data = 32; // offsetof(PyBytesObject, ob_sval)
  config.PyVarObject_size = 16; // offsetof(PyVarObject, ob_size)
  config.String_data = 40; // sizeof(PyASCIIObject)
  config.PyVersion_major = 3;
  config.PyVersion_minor = 12;
  config.PyVersion_micro = 4;
  config.PyCoroObject_cr_awaiter = 64; // offsetof(PyCoroObject, cr_ci_awaiter)
  config.PyGenObject_iframe = 80;
  config.PyFrameObject_owner = 70;

  return config;
}();

} // namespace facebook::strobelight::bpf_lib
