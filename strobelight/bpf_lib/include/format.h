// Copyright (c) Meta Platforms, Inc. and affiliates.

#ifndef __BPF_LIB_FORMAT_H__
#define __BPF_LIB_FORMAT_H__

#ifdef BPF_LIB_FORMAT_FMT

#include <fmt/format.h>
namespace bpf_lib_format = fmt;

#else // BPF_LIB_FORMAT_FMT

#include <format>
namespace bpf_lib_format = std;

#endif // BPF_LIB_FORMAT_FMT

#endif // __BPF_LIB_FORMAT_H__
