// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "strobelight/bpf_lib/util/pid_info/SharedPidInfo.h"

namespace facebook::pid_info {

template <typename T>
TSPidInfoT<T>::TSPidInfoT(pid_t pid, const std::string& rootDir)
    : T(pid, rootDir), mutex_() {}

/*
 * Methods which require non-const access to the underlying
 * pid_info::PidInfo.
 */

/*
 * Override properties
 */
template <typename T>
void TSPidInfoT<T>::setName(const std::string& name) {
  this->name_ = name;
}

template <typename T>
void TSPidInfoT<T>::setParentPid(pid_t ppid) {
  this->ppid_ = ppid;
}

template <typename T>
void TSPidInfoT<T>::setExe(const std::string& exe) {
  this->exe_ = exe;
}

// forward declare templates to be used
template class TSPidInfoT<pid_info::ProcPidInfo>;

} // namespace facebook::pid_info
