// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "strobelight/bpf_lib/util/pid_info/ProcUtil.h"

#include <sys/capability.h> // @manual
#include <sys/types.h>
#include <filesystem>
#include <map>
#include <string>
#include <vector>
#include "strobelight/bpf_lib/include/format.h"

#include "strobelight/bpf_lib/util/BpfLibLogger.h"
#include "strobelight/bpf_lib/util/pid_info/ProcPidInfo.h"

namespace facebook::pid_info {

using std::map;
using std::string;
using std::vector;

bool populateCgMap(
    map<string, string>& cg_map,
    vector<string>& subsystems,
    vector<string>& cg_names) {
  // We can't guess this alignment.
  if (subsystems.size() != cg_names.size()) {
    return false;
  }

  /*
   * skipping "net_cls", "freezer", "devices" and "cpu" for now as we don't use
   * those in prod.
   */
  vector<string> cgSubsystems = {"memory", "cpuset", "cpuacct", "blkio"};
  string colName;
  bool whitelisted;
  for (size_t i = 0; i < subsystems.size(); i++) {
    whitelisted = false;

    for (const auto& ss : cgSubsystems) {
      if (subsystems[i] == ss) {
        whitelisted = true;
        break;
      }
    }
    colName = subsystems[i] + "_cgroup";

    // We only care about non-whitelisted groups if they are non-root
    if (!whitelisted && cg_names[i] == "/") {
      continue;
    }

    cg_map[colName] = cg_names[i];
  }
  return (!cg_map.empty());
}

std::filesystem::path forceJoinNormalise(
    const std::filesystem::path& lhs,
    const std::filesystem::path& rhs) {
  std::filesystem::path base = lhs.empty() ? std::filesystem::path("/") : lhs;
  if (rhs.empty()) {
    return base;
  }
  if (rhs.is_relative()) {
    base /= rhs;
  }
  if (rhs.is_absolute()) {
    base += rhs;
  }
  return base.lexically_normal();
}

std::filesystem::path buildProcRelativePath(
    const std::filesystem::path& path,
    const std::filesystem::path& procRoot,
    const std::filesystem::path& procCwd) {
  if (path.is_absolute()) {
    return forceJoinNormalise(procRoot, path);
  }
  return forceJoinNormalise(procCwd, path);
}

bool haveEffectiveSysAdminCapability() {
  static bool result = [&] {
    std::array<char, 256> err_buf = {};
    cap_t caps = cap_get_proc();
    if (nullptr == caps) {
      strobelight_lib_print(
          STROBELIGHT_LIB_WARN,
          bpf_lib_format::format(
              "Error from cap_get_proc(): {}",
              strerror_r(errno, err_buf.data(), err_buf.max_size()))
              .c_str());
      return false;
    }

    cap_flag_value_t value;
    bool ret = false;
    int err = cap_get_flag(caps, CAP_SYS_ADMIN, CAP_EFFECTIVE, &value);
    if (0 != err) {
      strobelight_lib_print(
          STROBELIGHT_LIB_WARN,
          bpf_lib_format::format(
              "Error from cap_get_flag(CAP_SYS_ADMIN, CAP_EFFECTIVE): {}",
              strerror_r(errno, err_buf.data(), err_buf.max_size()))
              .c_str());
    } else {
      ret = CAP_SET == value;
      strobelight_lib_print(
          STROBELIGHT_LIB_INFO,
          bpf_lib_format::format(
              "Process {} CAP_SYS_ADMIN", (ret ? "has" : "does not have"))
              .c_str());
    }

    cap_free(caps);

    return ret;
  }();

  return result;
}

} // namespace facebook::pid_info
