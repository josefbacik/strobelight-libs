// Copyright (c) Meta Platforms, Inc. and affiliates.

#ifndef __BPF_LIB_ISTACKREADER_H__
#define __BPF_LIB_ISTACKREADER_H__

#include <unistd.h>
#include <set>
#include <vector>

namespace facebook::strobelight::bpf_lib {

enum HandleSampleResult {
  // successfully processed the sample
  SUCCESS,

  // the sample was not of the same type as the handler
  INCORRECT_TYPE,

  // the sample was not valid / could not be unpacked
  INVALID_SAMPLE,
};

struct StackEntry {
  std::string functionName;
  std::string fileName;
  size_t lineNumber;
};

class IStackReader {
 public:
  virtual ~IStackReader() {}

  virtual void init(const std::set<pid_t>& pids) = 0;
  virtual HandleSampleResult handleSample(
      void* sample,
      std::vector<StackEntry>& stack) = 0;
  virtual void postProcess() = 0;
};

} // namespace facebook::strobelight::bpf_lib

#endif
