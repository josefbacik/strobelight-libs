// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <utility>

#include "strobelight/bpf_lib/util/pid_info/ProcPidInfo.h" // @manual

namespace facebook::pid_info {

/*
 * TSPidInfoT is a templatized subclass of pid_info::PidInfo-type base class
 * that supports thread-safe access. Methods already const in the base class are
 * fine as is. Any non-const methods (used by Strobelight) have const overrides
 * added with exclusive access to those methods (and corresponding members)
 * guarded by a mutex.
 *
 * In addition, setters are added for a few basic process properties so that
 * they can be populated by means other than a live process / procfs.
 */
template <typename T>
class TSPidInfoT : public T {
 private:
  // Disable direct creation of SharedPidInfo. Always use SharedPidInfoCache for
  // consistency and so that procfs doesn't need to be parsed more than once for
  // the same process.
  explicit TSPidInfoT(pid_t pid, const std::string& rootDir = "");

  friend class SharedPidInfoCache;

 public:
  /*
   * Below are methods which require non-const access to the underlying
   * pid_info::PidInfo. We enable access to these
   * methods to be thread-safe by adding a const override for each that acquires
   * a mutex before calling the original non-const method in the base class.
   * This is built on the assumption that even though the PidInfo will be
   * mutated (e.g. Lazy) it will only affect members used by that method or
   * other non-const methods that will end up being protected by the same mutex.
   */
  template <typename Logger>
  void setProcessAndExeFieldsOnLogger(Logger& l) const {
    withMutableBase(
        [&](T* mbase) { mbase->setProcessAndExeFieldsOnLogger(l); });
  }

  template <typename Logger>
  void setProcessFieldsOnLogger(Logger& l) const {
    withMutableBase([&](T* mbase) { mbase->setProcessFieldsOnLogger(l); });
  }

  /*
   * Overrides for setting values.
   */

  void setName(const std::string& name);

  void setParentPid(pid_t ppid);

  void setExe(const std::string& exe);

  friend std::ostream& operator<<(
      std::ostream& out,
      const TSPidInfoT& pidInfo) {
    return out << pidInfo.getName() << " [" << pidInfo.getPid() << "]";
  }

 private:
  mutable std::mutex mutex_; // for serializing non-const access

  mutable Lazy<std::optional<std::string>> formattedCmdline_;

  template <class Function>
  auto withMutableBase(Function&& function) const {
    std::lock_guard<std::mutex> guard(mutex_);
    return function(static_cast<T*>(const_cast<TSPidInfoT*>(this)));
  }
};

using TSPidInfo = TSPidInfoT<pid_info::ProcPidInfo>;

using SharedPidInfo = const TSPidInfo;

} // namespace facebook::pid_info
