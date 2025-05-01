// Copyright (c) Meta Platforms, Inc. and affiliates.

#ifndef __FUNCTIONSOURCE_H__
#define __FUNCTIONSOURCE_H__

namespace facebook::strobelight::bpf_lib::python {
enum FrameMetadata { USER, KERNEL, UNKNOWN };

struct FunctionSource {
  std::string file;
  uint32_t line;
  FrameMetadata metadata;
  bool inlined;

  FunctionSource() : file(), line(0), metadata(UNKNOWN), inlined(false) {}

  FunctionSource(const std::string& file_, uint32_t line_)
      : file(file_), line(line_), metadata(USER), inlined(false) {}

  FunctionSource(
      const std::string& file_,
      uint32_t line_,
      FrameMetadata metadata_,
      bool inlined_)
      : file(file_), line(line_), metadata(metadata_), inlined(inlined_) {}
};

} // namespace facebook::strobelight::bpf_lib::python

#endif
