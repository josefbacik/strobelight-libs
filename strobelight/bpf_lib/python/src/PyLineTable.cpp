// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "strobelight/bpf_lib/python/include/PyLineTable.h"
#include "strobelight/bpf_lib/util/BpfLibLogger.h"
#include "strobelight/bpf_lib/util/pid_info/SharedPidInfo.h"

#include <fmt/format.h>
#include <sys/types.h>
#include <cstdlib>

namespace facebook::strobelight::bpf_lib::python {

static constexpr size_t kMaxLineTableSize = 1 * 1024 * 1024;
static constexpr size_t kPyCodeUnitSize = 2;

PyLineTable::PyLineTable(
    pid_info::SharedPidInfo& pidInfo,
    uint32_t firstLine,
    uintptr_t addr,
    size_t length)
    : entries_(), firstLine_(firstLine) {
  if (length > kMaxLineTableSize) {
    strobelight_lib_print(
        STROBELIGHT_LIB_INFO,
        fmt::format(
            "Bad line table size ({} bytes) in process {}",
            length,
            pidInfo.getPid())
            .c_str());
    return;
  }

  std::vector<uint8_t> data(length);
  if (pidInfo.readMemory(data.data(), (void*)addr, length) == (ssize_t)length) {
    initFromBytes(data.data(), length);
  } else {
    strobelight_lib_print(
        STROBELIGHT_LIB_INFO,
        fmt::format(
            "Failed to read {} byte line table at {:#x} in process ",
            length,
            addr,
            pidInfo.getPid())
            .c_str());
    return;
  }
}

PyLineTable::PyLineTable(uint32_t firstLine, const void* data, size_t len)
    : entries_(), firstLine_(firstLine) {
  initFromBytes((const uint8_t*)data, len);
}

void PyLineTable::initFromBytes(const uint8_t* buf, size_t length) {
  entries_.resize(length / 2);
  for (size_t ii = 0; ii < length; ii += 2) {
    size_t jj = ii / 2;
    entries_[jj].offsetDelta = buf[ii];
    entries_[jj].lineDelta = (int8_t)buf[ii + 1];
  }
}

uint32_t PyLineTable::getLineForInstIndex(int addrq) const {
  // See:
  // https://github.com/python/cpython/blob/3.10/Objects/lnotab_notes.txt#L57-L79
  //
  // NOTE: the format has changed in Python 3.11 to a (more) compressed format:
  // https://github.com/python/cpython/pull/91666/files
  // See py-spy for details on how to parse it.

  if (addrq < 0) {
    return firstLine_;
  }
  uintptr_t offset = addrq * kPyCodeUnitSize;
  uint32_t line = firstLine_;
  uintptr_t start, end = 0;
  for (const auto& entry : entries_) {
    if (entry.lineDelta == 0) {
      end += entry.offsetDelta;
      continue;
    }
    start = end;
    end = start + entry.offsetDelta;
    if (entry.lineDelta == -128) {
      // No valid line number -- skip entry
      continue;
    }
    line += entry.lineDelta;
    if (end == start) {
      // Empty range, omit.
      continue;
    }
    if (start <= offset && offset < end) {
      return line;
    }
  }

  return 0;
}

} // namespace facebook::strobelight::bpf_lib::python
