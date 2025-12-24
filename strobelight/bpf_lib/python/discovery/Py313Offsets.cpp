// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "strobelight/bpf_lib/python/include/OffsetConfig.h"

namespace facebook::strobelight::bpf_lib {

// clang-format off
//
// Python 3.13 offsets - based on Python 3.12 with updates for 3.13 changes
//
// Key changes in 3.13:
// - PyThreadState structure changes for free-threaded builds
// - Some internal frame structure changes
//
// clang-format on

/*
Items that no longer exist in 3.13 (same as 3.12):
- PyThreadState_frame, replaced by PyThreadState_cframe, and
_PyCFrame_current_frame
- PyFrameObject_back (exists but stack walking is done using the
InterpreterFrame)
- PyFrameObject_code, replaced by PyInterpreterFrame_code
- PyFrameObject_lasti, replaced by PyInterpreterFrame_prev_instr
- PyFrameObject_localsplus, replaced by PyInterpreterFrame_localsplus

Deprecated offsets:
- PyFrameObject_gen, replaced by runtime function _PyFrame_GetGenerator().
- PyCodeObject_varnames

GIL tracking changes in 3.13:
- The GIL moved from _PyRuntimeState.ceval.gil to PyInterpreterState._gil
- PyGIL_offset and PyGIL_last_holder are no longer applicable
- Use PyRuntimeState_interpreters_head to get main interpreter, then
  PyInterpreterState_gil_locked and PyInterpreterState_gil_last_holder
*/

extern const OffsetConfig kPy313OffsetConfig = [] {
  OffsetConfig config;
  config.PyObject_type = 8; // offsetof(PyObject, ob_type)
  config.PyTypeObject_name = 24; // offsetof(PyTypeObject, tp_name)

  // Python 3.13: current_frame is directly in PyThreadState (no cframe wrapper)
  // PyThreadState layout:
  //   prev(0), next(8), interp(16), eval_breaker(24), _status(32),
  //   _whence(36), state(40), py_recursion_remaining(44), py_recursion_limit(48),
  //   c_recursion_remaining(52), recursion_headroom(56), tracing(60),
  //   what_event(64), padding(68), current_frame(72)
  config.PyThreadState_cframe = 72; // offsetof(PyThreadState, current_frame)
  config.PyThreadState_thread = 152; // offsetof(PyThreadState, thread_id)
  config.PyThreadState_interp = 16; // offsetof(PyThreadState, interp)
  config.PyInterpreterState_modules =
      944; // offsetof(PyInterpreterState, modules)

  // Set to BPF_LIB_DEFAULT_FIELD_OFFSET to skip the second dereference
  // (current_frame is directly in PyThreadState, not wrapped in cframe)
  config._PyCFrame_current_frame = BPF_LIB_DEFAULT_FIELD_OFFSET;

  // _PyInterpreterFrame offsets (f_executable replaces f_code in 3.13)
  config.PyInterpreterFrame_code = 0; // offsetof(_PyInterpreterFrame, f_executable)
  config.PyInterpreterFrame_previous =
      8; // offsetof(_PyInterpreterFrame, previous)
  config.PyInterpreterFrame_localsplus =
      72; // offsetof(_PyInterpreterFrame, localsplus)
  config.PyInterpreterFrame_prev_instr =
      56; // offsetof(_PyInterpreterFrame, instr_ptr)

  // PyCodeObject offsets
  config.PyCodeObject_co_flags = 48; // offsetof(PyCodeObject, co_flags)
  config.PyCodeObject_filename = 112; // offsetof(PyCodeObject, co_filename)
  config.PyCodeObject_name = 120; // offsetof(PyCodeObject, co_name)
  config.PyCodeObject_qualname = 128; // offsetof(PyCodeObject, co_qualname)
  config.PyCodeObject_linetable = 136; // offsetof(PyCodeObject, co_linetable)
  config.PyCodeObject_firstlineno =
      68; // offsetof(PyCodeObject, co_firstlineno)
  config.PyCodeObject_code_adaptive =
      200; // offsetof(PyCodeObject, co_code_adaptive) - after co_extra(192)

  config.PyTupleObject_item = 24; // offsetof(PyTupleObject, ob_item)
  // Python 3.13 added _Py_DebugOffsets at the start of _PyRuntimeState,
  // shifting all subsequent fields. autoTSSkey._key is now at offset 2164.
  config.TLSKey_offset = 2164; // offsetof(_PyRuntimeState, autoTSSkey._key)
  config.PyBytesObject_data = 32; // offsetof(PyBytesObject, ob_sval)
  config.PyVarObject_size = 16; // offsetof(PyVarObject, ob_size)
  config.String_data = 40; // sizeof(PyASCIIObject)
  config.PyVersion_major = 3;
  config.PyVersion_minor = 13;
  config.PyVersion_micro = 0;
  config.PyCoroObject_cr_awaiter = 64; // offsetof(PyCoroObject, cr_ci_awaiter)
  config.PyGenObject_iframe = 80;
  config.PyFrameObject_owner = 70;

  // Python 3.13 GIL tracking: GIL moved from _PyRuntimeState to PyInterpreterState
  // offsetof(_PyRuntimeState, interpreters.head) = 632
  config.PyRuntimeState_interpreters_head = 632;
  // offsetof(PyInterpreterState, _gil.locked) = 7768
  config.PyInterpreterState_gil_locked = 7768;
  // offsetof(PyInterpreterState, _gil.last_holder) = 7760
  config.PyInterpreterState_gil_last_holder = 7760;

  return config;
}();

} // namespace facebook::strobelight::bpf_lib
