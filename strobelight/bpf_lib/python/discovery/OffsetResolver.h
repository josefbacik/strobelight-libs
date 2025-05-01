// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <unordered_map>
#include <unordered_set>
#include <variant>

#include "strobelight/bpf_lib/python/include/OffsetConfig.h"
#include "strobelight/bpf_lib/util/ElfFile.h"

#include "strobelight/bpf_lib/python/discovery/PyOffsets.h"

namespace facebook::strobelight::bpf_lib {

// Where is OffsetResolver getting its offsets from?
// If a 'Mixed' strategy is ever implemented this enum should
// be extended
enum class OffsetResolutionStrategy { Headers, Process };

struct OffsetResolution {
  OffsetConfig offsets;
  OffsetResolutionStrategy resolutionStrategy;
};

struct ProcSymInfo {
  // location of OffsetConfig struct member so we can directly write 'size'
  // bytes in memory instead of accessing it by name
  std::variant<int32_t*, uintptr_t*> addr;
  // Probably don't want to do anything if we see the symbol twice
  bool seen = false;
  bool required = true;
};

class OffsetResolver {
 public:
  OffsetResolver();

  // disable copying because addresses in symbolNameToInfo_ will be invalid
  OffsetResolver(const OffsetResolver&) = delete;
  OffsetResolver& operator=(const OffsetResolver&) = delete;

  void maybeAddProcessOffsetSymbol(
      const strobelight::ElfFile& elf,
      const strobelight::ElfFile::Symbol& symbol);
  template <typename T>
  void maybeAddProcessOffsetVal(const std::string& name, T& val);
  void mergeOffsetResolver(const OffsetResolver& offsetResolver);

  void setHeaderOffsets(const std::string_view versionString);

  static std::unordered_set<std::string> getProcessOffsetSymbolNames();

  bool allProcessOffsetsFound() const;

  OffsetResolution resolveOffsets(bool forceHeaderOffsets = false) const;

 private:
  template <typename T>
  static void setOffsetVal(
      const strobelight::ElfFile& elf,
      const strobelight::ElfFile::Symbol& symbol,
      T* addr);

  bool headerOffsetsFound_{false};

  OffsetConfig headerOffsets_;
  OffsetConfig processOffsets_;

  // Modify population of this in constructor if there are new symbols in
  // OffsetConfig to grab from process symbols
  std::unordered_map<std::string, ProcSymInfo> symbolNameToInfo_;

  static const OffsetConfig& getHeaderOffsetsForVersion(
      const std::string_view versionString);
};

} // namespace facebook::strobelight::bpf_lib
