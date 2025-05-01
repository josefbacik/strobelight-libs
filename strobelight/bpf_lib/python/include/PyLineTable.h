// Copyright (c) Meta Platforms, Inc. and affiliates.

#ifndef __PY_LINE_TABLE_H__
#define __PY_LINE_TABLE_H__

#include <sys/types.h>
#include <cstdlib>
#include <optional>
#include "strobelight/bpf_lib/util/pid_info/SharedPidInfo.h"

namespace facebook::strobelight::bpf_lib::python {

class PyLineTable {
 public:
  PyLineTable(uint32_t firstLine, const void* data, size_t length);

  PyLineTable(
      pid_info::SharedPidInfo& pidInfo,
      uint32_t firstLine,
      uintptr_t addr,
      size_t length);

  uint32_t getLineForInstIndex(int addrq) const;

 private:
  struct PyLineTableEntry {
    uint8_t offsetDelta;
    int8_t lineDelta;
  };
  std::vector<PyLineTableEntry> entries_;
  uint32_t firstLine_;

  void initFromBytes(const uint8_t* data, size_t length);
};

} // namespace facebook::strobelight::bpf_lib::python

#endif // __PY_LINE_TABLE_H__
