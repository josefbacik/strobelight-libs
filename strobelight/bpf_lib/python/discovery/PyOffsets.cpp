// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <ostream>
#include "strobelight/bpf_lib/python/include/OffsetConfig.h"

namespace facebook::strobelight::bpf_lib {

std::ostream& operator<<(std::ostream& os, const OffsetConfig& offsets) {
  os << "OffsetConfig:" << std::endl;
  os << "\t OffsetConfig.PyObject_type : " << offsets.PyObject_type
     << std::endl;
  os << "\t OffsetConfig.PyTypeObject_name : " << offsets.PyTypeObject_name
     << std::endl;
  os << "\t OffsetConfig.PyThreadState_frame : " << offsets.PyThreadState_frame
     << std::endl;
  os << "\t OffsetConfig.PyThreadState_shadow_frame : "
     << offsets.PyThreadState_shadow_frame << std::endl;
  os << "\t OffsetConfig.PyThreadState_thread : "
     << offsets.PyThreadState_thread << std::endl;
  os << "\t OffsetConfig.PyFrameObject_back : " << offsets.PyFrameObject_back
     << std::endl;
  os << "\t OffsetConfig.PyFrameObject_code : " << offsets.PyFrameObject_code
     << std::endl;
  os << "\t OffsetConfig.PyFrameObject_lasti : " << offsets.PyFrameObject_lasti
     << std::endl;
  os << "\t OffsetConfig.PyFrameObject_localsplus : "
     << offsets.PyFrameObject_localsplus << std::endl;
  os << "\t OffsetConfig.PyFrameObject_gen : " << offsets.PyFrameObject_gen
     << std::endl;
  os << "\t OffsetConfig.PyGenObject_gi_shadow_frame : "
     << offsets.PyGenObject_gi_shadow_frame << std::endl;
  os << "\t OffsetConfig.PyCodeObject_co_flags : "
     << offsets.PyCodeObject_co_flags << std::endl;
  os << "\t OffsetConfig.PyCodeObject_filename : "
     << offsets.PyCodeObject_filename << std::endl;
  os << "\t OffsetConfig.PyCodeObject_name : " << offsets.PyCodeObject_name
     << std::endl;
  os << "\t OffsetConfig.PyCodeObject_varnames : "
     << offsets.PyCodeObject_varnames << std::endl;
  os << "\t OffsetConfig.PyCodeObject_firstlineno : "
     << offsets.PyCodeObject_firstlineno << std::endl;
  os << "\t OffsetConfig.PyCodeObject_linetable : "
     << offsets.PyCodeObject_linetable << std::endl;
  os << "\t OffsetConfig.PyCodeObject_code_adaptive : "
     << offsets.PyCodeObject_code_adaptive << std::endl;
  os << "\t OffsetConfig.PyCodeObject_qualname : "
     << offsets.PyCodeObject_qualname << std::endl;
  os << "\t OffsetConfig.PyTupleObject_item : " << offsets.PyTupleObject_item
     << std::endl;
  os << "\t OffsetConfig.PyCoroObject_cr_awaiter : "
     << offsets.PyCoroObject_cr_awaiter << std::endl;
  os << "\t OffsetConfig.PyShadowFrame_prev : " << offsets.PyShadowFrame_prev
     << std::endl;
  os << "\t OffsetConfig.PyShadowFrame_data : " << offsets.PyShadowFrame_data
     << std::endl;
  os << "\t OffsetConfig.PyShadowFrame_PtrMask : "
     << offsets.PyShadowFrame_PtrMask << std::endl;
  os << "\t OffsetConfig.PyShadowFrame_PtrKindMask : "
     << offsets.PyShadowFrame_PtrKindMask << std::endl;
  os << "\t OffsetConfig.PyShadowFrame_PYSF_CODE_RT : "
     << offsets.PyShadowFrame_PYSF_CODE_RT << std::endl;
  os << "\t OffsetConfig.PyShadowFrame_PYSF_PYCODE : "
     << offsets.PyShadowFrame_PYSF_PYCODE << std::endl;
  os << "\t OffsetConfig.PyShadowFrame_PYSF_PYFRAME : "
     << offsets.PyShadowFrame_PYSF_PYFRAME << std::endl;
  os << "\t OffsetConfig.PyShadowFrame_PYSF_RTFS : "
     << offsets.PyShadowFrame_PYSF_RTFS << std::endl;
  os << "\t OffsetConfig.CodeRuntime_py_code : " << offsets.CodeRuntime_py_code
     << std::endl;
  os << "\t OffsetConfig.RuntimeFrameState_py_code : "
     << offsets.RuntimeFrameState_py_code << std::endl;
  os << "\t OffsetConfig.String_data : " << offsets.String_data << std::endl;
  os << "\t OffsetConfig.TLSKey_offset : " << offsets.TLSKey_offset
     << std::endl;
  os << "\t OffsetConfig.TCurrentState_offset : "
     << offsets.TCurrentState_offset << std::endl;
  os << "\t OffsetConfig.PyGIL_offset : " << offsets.PyGIL_offset << std::endl;
  os << "\t OffsetConfig.PyGIL_last_holder : " << offsets.PyGIL_last_holder
     << std::endl;
  os << "\t OffsetConfig.PyBytesObject_data : " << offsets.PyBytesObject_data
     << std::endl;
  os << "\t OffsetConfig.PyVarObject_size : " << offsets.PyVarObject_size
     << std::endl;
  os << "\t OffsetConfig.PyFrameObject_owner : " << offsets.PyFrameObject_owner
     << std::endl;
  os << "\t OffsetConfig.PyGenObject_iframe : " << offsets.PyGenObject_iframe
     << std::endl;
  os << "\t OffsetConfig.PyVersion_major : " << offsets.PyVersion_major
     << std::endl;
  os << "\t OffsetConfig.PyVersion_minor : " << offsets.PyVersion_minor
     << std::endl;
  os << "\t OffsetConfig.PyVersion_micro : " << offsets.PyVersion_micro
     << std::endl;

  return os;
}

} // namespace facebook::strobelight::bpf_lib
