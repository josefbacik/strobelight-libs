// Copyright (c) Meta Platforms, Inc. and affiliates.

#ifndef __BPF_LIB_STACKREADERBASE_H__
#define __BPF_LIB_STACKREADERBASE_H__

#include "strobelight/bpf_lib/include/IStackReader.h"
#include "strobelight/bpf_lib/include/structs.h"

#define BPF_LIB_SAMPLE_NONE 0

namespace facebook::strobelight::bpf_lib {

template <typename SkelType, typename SampleType>
class StackReaderBase : public IStackReader {
 public:
  StackReaderBase(SkelType* skel, uint16_t type) : skel_(skel), type_(type) {}

  virtual ~StackReaderBase() override {}

 protected:
  SkelType* skel_{nullptr};

  uint16_t type_{BPF_LIB_SAMPLE_NONE};

  SampleType* convertHeader(void* buffer) const {
    auto header = reinterpret_cast<struct sample_header*>(buffer);
    if (type_ == header->type) {
      return reinterpret_cast<SampleType*>(header);
    }
    return nullptr;
  }
};

} // namespace facebook::strobelight::bpf_lib

#endif
