// Copyright (c) Meta Platforms, Inc. and affiliates.

#ifndef __PYSTACKSTRUCTS_H__
#define __PYSTACKSTRUCTS_H__

#include <optional>
#include "strobelight/bpf_lib/python/include/PyLineTable.h"

namespace facebook::strobelight::bpf_lib::python {

struct PySymbol {
  std::string funcname;
  std::string filename;
  std::optional<PyLineTable> linetable;
};

} // namespace facebook::strobelight::bpf_lib::python

#endif
