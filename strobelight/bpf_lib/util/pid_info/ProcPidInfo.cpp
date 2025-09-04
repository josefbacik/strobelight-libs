// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "strobelight/bpf_lib/util/pid_info/ProcPidInfo.h"

#include <fmt/format.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <exception>
#include <filesystem>
#include <fstream>
#include <optional>
#include <ranges>
#include <stdexcept>
#include <string_view>

#include "strobelight/bpf_lib/util/BpfLibLogger.h"
#include "strobelight/bpf_lib/util/pid_info/ProcUtil.h"

namespace {
/* Primarily used to read files from /proc filesystem.
 * These typically do not behave like normal files. For example,
 * typical methodology for getting the size of the file will report
 * 0. To assuage this, we have a fallback size of 2048 which _should_
 * accommodate most files, but will grow that up to 3x should the need
 * arise.
 */
size_t readFile(const std::string& filename, std::string& output) {
  output.clear();
  std::ifstream file(filename, std::ios::in | std::ios::binary);
  if (!file) {
    return 0;
  }

  file.seekg(0, std::ios::end);

  int64_t fileSize = 0;

  if (file.fail()) {
    // /proc files report size 0. set a min size of 2048
    // which should be able to accommodate most /proc/<pid>/status
    fileSize = 2048;
    file.clear();
  } else {
    fileSize = static_cast<int64_t>(file.tellg()) + 1;
    file.seekg(0);
  }

  int64_t readSize = 0;
  for (int idx = 1; idx < 4 && file.good(); ++idx) {
    output.resize(idx * fileSize);
    file.read(&output[readSize], fileSize - readSize);

    readSize += file.gcount();
  }

  if (!file.bad() && file.eof()) {
    // we got to the end of the file with no errors
    output.resize(readSize);
    return readSize;
  }

  output.clear();
  return 0;
}

} // namespace

namespace facebook::pid_info {

namespace fs = std::filesystem;

static constexpr std::string_view kAnonHugePage = "/anon_hugepage";

// /proc/PID/status fields
static constexpr std::string_view kNamePrefix = "Name:\t";
static constexpr std::string_view kStatePrefix = "State:\t";
static constexpr std::string_view kPPidPrefix = "PPid:\t";
static constexpr std::string_view kUidPrefix = "Uid:\t";
static constexpr std::string_view kGidPrefix = "Gid:\t";
static constexpr std::string_view kTgidPrefix = "Tgid:\t";
static constexpr std::string_view kNSPidPrefix = "NSpid:\t";
static constexpr std::string_view kNSTgidPrefix = "NStgid:\t";
static constexpr std::string_view kVmSizePrefix = "VmSize:\t";
static constexpr std::string_view kVmHwmPrefix = "VmHWM:\t";
static constexpr std::string_view kVmRssPrefix = "VmRSS:\t";
static constexpr std::string_view kSigBlkPrefix = "SigBlk:\t";
static constexpr std::string_view kSigIgnPrefix = "SigIgn:\t";
static constexpr std::string_view kSigCgtPrefix = "SigCgt:\t";
static constexpr std::string_view kRssAnonPrefix = "RssAnon:\t";
static constexpr std::string_view kRssFilePrefix = "RssFile:\t";
static constexpr std::string_view kRssShmemPrefix = "RssShmem:\t";

static constexpr std::string_view kPssPrefix = "Pss:";
static constexpr std::string_view kPssAnonPrefix = "Pss_Anon:";
static constexpr std::string_view kPssFilePrefix = "Pss_File:";
static constexpr std::string_view kPssShmemPrefix = "Pss_Shmem:";
static constexpr std::string_view kSwapPssPrefix = "SwapPss:";
static constexpr std::string_view kAnonHugePagePrefix = "AnonHugePages:";

static constexpr std::string_view kMemPattern = "%lu kB";

static constexpr std::string_view kDeleted = " (deleted)";

static constexpr std::string_view kKernelName = "kernel";
static constexpr std::string_view kKernelExe = "vmlinux";

static constexpr std::string_view kMemStatFormat = "{} kB";

// Positions of various fields in /proc/[pid]/stat line
// http://man7.org/linux/man-pages/man5/proc.5.html
enum ProcStatFields {
  PROC_STAT_FIELD_UTIME = 14,
  PROC_STAT_FIELD_STIME = 15,
  PROC_STAT_FIELD_NUM_THREADS = 20,
  PROC_STAT_FIELD_STARTTIME = 22,
  PROC_STAT_FIELD_RSS = 24
};

namespace {
std::string_view getLast(char ch, std::string_view line) {
  if (line.empty()) {
    return {};
  }
  size_t last = 0;
  auto lastCh = line.rfind(ch);
  if (lastCh != std::string::npos) {
    last = lastCh + 1;
  }
  return line.substr(last);
}

bool readSymlink(const std::string& linkname, std::string* filename) {
  char buff[PATH_MAX + 1];
  ssize_t ret = readlink(linkname.c_str(), buff, sizeof(buff));
  if (ret == -1) {
    return false;
  }
  // Paths longer than buffer size is dangerous.
  // To prevent partial-legal paths, we clear the response.
  if (static_cast<size_t>(ret) >= sizeof(buff)) {
    buff[0] = '\0';
  } else {
    buff[ret] = '\0';
  }
  *filename = buff;
  return true;
}

fs::path getActualProcFsPath(const fs::path& rootDir) {
  static constexpr std::string_view kProcDir = "/proc";
  return forceJoinNormalise(rootDir, kProcDir);
}

bool removePrefix(std::string_view& s, std::string_view prefix) {
  if (s.starts_with(prefix)) {
    s.remove_prefix(prefix.size());
    return true;
  }
  return false;
}

bool removeSuffix(std::string_view& s, std::string_view suffix) {
  if (s.ends_with(suffix)) {
    s.remove_suffix(suffix.size());
    return true;
  }
  return false;
}

bool trimWhitespace(std::string_view& str) {
  constexpr std::string_view ws = " \t\r\n";
  size_t pos;
  pos = str.find_first_not_of(ws);
  if (pos == str.npos) {
    return false;
  }
  str.remove_prefix(pos);
  pos = str.find_last_not_of(ws);
  if (pos == str.npos) {
    return false;
  }
  str.remove_suffix(str.size() - pos - 1);
  return true;
}

} // namespace

ProcPidInfo::ProcPidInfo(pid_t pid, std::string rootDir)
    : pid_(pid), rootDir_(std::move(rootDir)), validInfo_(false) {
  if (pid == 0) {
    exe_ = kKernelExe;
    name_ = kKernelName;
    return;
  }

  // Read basic Process attributes, as well as Process stats including
  // CPU time, RSS, Thread count, etc.
  validInfo_ = readProcInfo() && readProcStat();
  if (!validInfo_) {
    return;
  }

  if (!isKernelProcess()) {
    // Read /proc/<PID>/exe symlink to get binary path
    readProcExe();
  }
}

ProcPidInfo::ProcPidInfo(std::string rootDir)
    : pid_(-1), rootDir_(std::move(rootDir)) {}

ProcPidInfo::~ProcPidInfo() = default;

bool ProcPidInfo::readProcfsFileToString(
    const std::string& filename,
    std::string* contents) {
  std::error_code ec{};
  bool const result = std::filesystem::exists(filename, ec) &&
      readFile(filename, *contents) > 0;
  if (!result) {
    *contents = "";
  }
  return result;
}

bool ProcPidInfo::readProcfsSymlink(
    const std::string& linkname,
    std::string* filename) {
  filename->clear();
  std::error_code ec{};
  bool const result = std::filesystem::is_symlink(linkname, ec) &&
      readSymlink(linkname, filename);
  return result;
}

bool ProcPidInfo::isAlive() const {
  std::error_code ec{};
  return std::filesystem::exists(getProcfsPath("status"), ec);
}

pid_t ProcPidInfo::getPid() const {
  return pid_;
}

pid_t ProcPidInfo::getNSPid() const {
  return nspid_;
}

const std::string& ProcPidInfo::getName() const {
  return name_;
}

const std::string& ProcPidInfo::getState() const {
  return state_;
}

uid_t ProcPidInfo::getUid() const {
  return uid_;
}

gid_t ProcPidInfo::getGid() const {
  return gid_;
}

pid_t ProcPidInfo::getParentPid() const {
  return ppid_;
}

pid_t ProcPidInfo::getThreadGroupId() const {
  return tgid_;
}

pid_t ProcPidInfo::getNSThreadGroupId() const {
  return nstgid_;
}

std::string ProcPidInfo::getVmSize() const {
  return fmt::format(kMemStatFormat, getVmSizeBytes() / 1024ULL);
}

std::string ProcPidInfo::getVmHwm() const {
  return fmt::format(kMemStatFormat, getVmHwmBytes() / 1024ULL);
}

std::string ProcPidInfo::getVmRss() const {
  return fmt::format(kMemStatFormat, getVmRssBytes() / 1024ULL);
}

std::string ProcPidInfo::getRssAnon() const {
  return fmt::format(kMemStatFormat, getRssAnonBytes() / 1024ULL);
}

std::string ProcPidInfo::getRssFile() const {
  return fmt::format(kMemStatFormat, getRssFileBytes() / 1024ULL);
}

std::string ProcPidInfo::getRssShmem() const {
  return fmt::format(kMemStatFormat, getRssShmemBytes() / 1024ULL);
}

std::string ProcPidInfo::getAnonHugePage() const {
  return fmt::format(kMemStatFormat, getAnonHugePageBytes() / 1024ULL);
}

uint64_t ProcPidInfo::getVmSizeBytes() const {
  return vmsize_;
}

uint64_t ProcPidInfo::getVmHwmBytes() const {
  return vmhwm_;
}

uint64_t ProcPidInfo::getVmRssBytes() const {
  return vmrss_;
}

uint64_t ProcPidInfo::getRssAnonBytes() const {
  return rssanon_;
}

uint64_t ProcPidInfo::getRssFileBytes() const {
  return rssfile_;
}

uint64_t ProcPidInfo::getRssShmemBytes() const {
  return rssshmem_;
}

uint64_t ProcPidInfo::getPssBytes() const {
  return pss_;
}

uint64_t ProcPidInfo::getPssAnonBytes() const {
  return pssanon_;
}

uint64_t ProcPidInfo::getPssFileBytes() const {
  return pssfile_;
}

uint64_t ProcPidInfo::getPssShmemBytes() const {
  return pssshmem_;
}

uint64_t ProcPidInfo::getSwapPssBytes() const {
  return swappss_;
}

uint64_t ProcPidInfo::getAnonHugePageBytes() const {
  return anonhugepage_;
}

namespace {
bool testSig(uint64_t sigbits, int signum) {
  return (sigbits & 1ULL << (signum - 1)) != 0U;
}
} // namespace

uint64_t ProcPidInfo::getSigBlk() const {
  return sigblk_;
}

bool ProcPidInfo::testSigBlk(int signum) const {
  return testSig(sigblk_, signum);
}

uint64_t ProcPidInfo::getSigIgn() const {
  return sigign_;
}

bool ProcPidInfo::testSigIgn(int signum) const {
  return testSig(sigign_, signum);
}

uint64_t ProcPidInfo::getSigCgt() const {
  return sigcgt_;
}

bool ProcPidInfo::testSigCgt(int signum) const {
  return testSig(sigcgt_, signum);
}

bool ProcPidInfo::isKernelProcessPid(
    pid_t pid,
    const fs::path& rootDir,
    pid_t ppid) {
  if (pid == 2 || pid == 0) {
    return true;
  }
  if (ppid == -1) {
    // Determine parent pid, since none was provided.
    auto path = getProcfsPathForPid(pid, "status", rootDir);
    std::fstream fs(path, std::ios_base::in);
    std::string line;
    while (std::getline(fs, line)) {
      if (line.starts_with(kPPidPrefix)) {
        auto value = std::string_view(line).substr(0, kPPidPrefix.size());
        value = getLast('\t', value);
        if (value.empty()) {
          return false;
        }

        if (!trimWhitespace(value)) {
          return false;
        }

        pid_t targetValue = 0;
        auto ec = std::from_chars(
                      value.data(), value.data() + value.size(), targetValue)
                      .ec;
        if (ec != std::errc{}) {
          return false;
        }
        ppid = targetValue;
        break;
      }
    }
  }
  return ppid == 2;
}

bool ProcPidInfo::isKernelProcess() const {
  return ppid_ == 2 || pid_ == 2 || pid_ == 0;
}

std::optional<std::string> ProcPidInfo::getExe() const {
  return exe_;
}

const Stats& ProcPidInfo::getStats() const {
  return stats_;
}

std::chrono::seconds ProcPidInfo::getStartTimeAfterBoot() const {
  return startTimeAfterBoot_;
}

std::chrono::system_clock::time_point ProcPidInfo::getStartTimeSystemClock()
    const {
  using namespace std::chrono;
  return startTime_.get([this](auto& val) {
    struct sysinfo sysInfo;
    sysinfo(&sysInfo); // no documented way for this to fail
    auto const uptime = seconds(sysInfo.uptime) - startTimeAfterBoot_;
    val = system_clock::now() - uptime;
  });
}

time_t ProcPidInfo::getStartTime() const {
  using namespace std::chrono;
  auto startTime = getStartTimeSystemClock();
  return duration_cast<seconds>(startTime.time_since_epoch()).count();
}

fs::path ProcPidInfo::getProcfsRoot(const fs::path& path) const {
  return forceJoinNormalise(getProcfsPath("root"), path);
}

std::optional<std::string> ProcPidInfo::getChrootPath() const {
  return chrootPath_.get([&](auto& val) {
    auto chroot = getProcfsRoot("");
    std::string path;
    if (readProcfsSymlink(chroot, &path)) {
      val = std::move(path);
    }
  });
}

std::optional<std::string> ProcPidInfo::getChrootRelativeExe() const {
  return relativeExe_.get([&](auto& val) {
    if (!exe_.has_value()) {
      val = exe_;
      return;
    }

    auto chrootPath = getChrootPath();
    if (!chrootPath.has_value() || chrootPath->empty() ||
        (chrootPath->size() == 1 && chrootPath->at(0) == '/')) {
      val = exe_;
      return;
    }

    auto exeSP = std::string_view(*exe_);
    removePrefix(exeSP, *chrootPath);
    val = exeSP;
  });
}

fs::path ProcPidInfo::getProcfsCwd() const {
  return getProcfsPath("cwd");
}

std::optional<std::vector<std::string>> ProcPidInfo::getCmdLine() const {
  // need to construct the string with length so it is not interpreted as empty
  static std::string null_delim("\0", 1);
  return cmdLine_.get([&](auto& val) {
    if (!isKernelProcess()) {
      auto fn = getProcfsPath("cmdline");
      std::string cmdline;
      if (!readProcfsFileToString(fn, &cmdline)) {
        return;
      }
      val = std::vector<std::string>();
      tokenize(cmdline, null_delim, val.value());
    }
  });
}

std::optional<std::string> ProcPidInfo::getPidNamespace() const {
  return pidNamespace_.get([&](auto& val) {
    auto path = getProcfsPath("ns/pid");
    std::string pidNamespace;
    if (!readProcfsSymlink(path, &pidNamespace)) {
      return;
    }
    val = pidNamespace;
  });
}

std::shared_ptr<std::map<std::string, std::string>> ProcPidInfo::getCgroups()
    const {
  return cgroups_.get([&](auto& val) {
    if (isKernelProcess()) {
      return;
    }

    auto path = getProcfsPath("cgroup");
    std::string raw;

    if (!readProcfsFileToString(path, &raw)) {
      return;
    }

    std::vector<std::string> cgLines;
    tokenize(raw, "\n", cgLines);

    val = std::make_unique<std::map<std::string, std::string>>();
    for (auto& line : cgLines) {
      std::vector<std::string> subsystems;
      std::vector<std::string> cgNames;

      if (!getCgroupNames(line, subsystems, cgNames)) {
        continue;
      }

      populateCgMap(*val, subsystems, cgNames);
    }
  });
}

fs::path ProcPidInfo::getProcfsPathForPid(
    pid_t pid,
    const std::string& option,
    const fs::path& rootDir) {
  // The need to add rootDir_ is for Unit Tests.
  return forceJoinNormalise(
      getActualProcFsPath(rootDir) / std::to_string(pid), option);
}

fs::path ProcPidInfo::getProcfsPath(const std::string& option) const {
  return getProcfsPathForPid(pid_, option, rootDir_);
}

bool ProcPidInfo::updateStats() {
  return validInfo_ = readProcStat();
}

bool ProcPidInfo::updateInfo() {
  return validInfo_ = readProcInfo();
}

bool ProcPidInfo::updatePssStats() {
  return readProcSmapsRollup();
}

// Returns vector of tids of active threads of the process
std::vector<pid_t> ProcPidInfo::getRunningThreads() const {
  auto path = getProcfsPath("task");
  std::vector<pid_t> result;
  auto success = readPidListFromDirectory(path, result);
  if (!success) {
    // This can easily happen if the PID does not exist, so we just fail
    // silently instead of throwing an exception
    strobelight_lib_print(
        STROBELIGHT_LIB_DEBUG,
        fmt::format(
            "Unable to read /proc/{}/task/. PID probably doesn't exist anymore",
            pid_)
            .c_str());
  }
  return result;
}

bool ProcPidInfo::readMemoryMapLine(
    const std::string& line,
    MemoryMapping& module) {
  char read;
  char write;
  char exec;
  char share;
  char buf[PATH_MAX + 1];
  buf[0] = '\0';
  auto res = std::sscanf(
      line.c_str(),
      // From Kernel source fs/proc/task_mmu.c
      "%lx-%lx %c%c%c%c %llx %lx:%lx %lu %[^\n]",
      &module.startAddr,
      &module.endAddr,
      &read,
      &write,
      &exec,
      &share,
      &module.fileOffset,
      &module.devMajor,
      &module.devMinor,
      &module.inode,
      buf);
  // The module name might be empty, where res would be 10 and buf untouched
  if (res < 10) {
    return false;
  }

  module.name = buf;
  module.readable = (read == 'r');
  module.writable = (write == 'w');
  module.executable = (exec == 'x');
  module.shared = (share == 's');

  return true;
}

bool ProcPidInfo::iterateAllMemoryMappings(
    MemoryMappingCallback callback) const {
  auto filename = getProcfsPath("maps");
  std::fstream fs(filename, std::ios_base::in);
  if (!fs.is_open()) {
    strobelight_lib_print(
        STROBELIGHT_LIB_DEBUG,
        fmt::format(
            "[{}] Unable to open procfs mapfile: '{}'",
            pid_,
            filename.filename().string())
            .c_str());
    return false;
  }

  MemoryMapping module;
  std::string line;
  while (std::getline(fs, line)) {
    if (!ProcPidInfo::readMemoryMapLine(line, module)) {
      strobelight_lib_print(
          STROBELIGHT_LIB_DEBUG,
          fmt::format(
              "[{}] Error reading line '{}' in {} procfs mapfile",
              pid_,
              line,
              filename.filename().string())
              .c_str());
      return false;
    }

    try {
      if (callback(module) == IterControl::BREAK) {
        break;
      }
    } catch (const std::exception& e) {
      strobelight_lib_print(
          STROBELIGHT_LIB_DEBUG,
          fmt::format(
              "[{}] Exception executing callback on line: '{}' in {} procfs mapfile. Message: {}.",
              pid_,
              line,
              filename.filename().string(),
              e.what())
              .c_str());
      return false;
    }
  }

  return true;
}

// Resolving from proc maps is trickier than just resolving the main exe
// directly, due to non-fixed load addresses. The basic algorithm used is as
// follows:
//   For each buildId/binary mapping in /proc/<pid>/maps get the entry
//   with the lowest startAddr (ignoring shared and non-readable mappings);
//   this should happen automatically because they are ordered this way.
//
//   For the buildId iterate over all the ELF program headers and get the
//   default load address (p_vaddr) and offset (p_offset) for the lowest
//   loadable (LOAD) segment. They should be in this order already.
//
//   In order to compute the 'slide'/base-load-address of a shared or
//   relocatable binary we will take the start address of the lowest
//   memory mapping and subtract the fileOffset of the same memory mapping
//   and then substract the difference between the p_vaddr and p_offset above:
//   slide = (mmStartAddr - mmFileOffset) - (lowest p_vaddr - lowest p_offset)
//
//   Most of the time mmFileOffset and lowest p_offset are the same.
//
//   Why?
//   From the ELF spec: https://refspecs.linuxfoundation.org/elf/elf.pdf
//   "Though the system chooses virtual addresses for individual processes, it
//   maintains the segments’ relative positions. Because position-independent
//   code uses relative addressing between segments, the difference between
//   virtual addresses in memory must match the difference between virtual
//   addresses in the file. The difference between the virtual address of any
//   segment in memory and the corresponding virtual address in the file is thus
//   a single constant value for any one executable or shared object in a given
//   process."
//
//   This essentialy means that the base-load-address for each binary (within
//   the context of a process) is the same for all of its memory mappings in
//   order to maintain relative addressing. So all we have to do is find the
//   lowest mapping for each binary, then subtract the fileOffset to get the
//   absolute address that corresponds to file offset zero, then subtract the
//   difference between the default load address (p_vaddr) and the fileOffset
//   (p_offset) from the lowest LOAD segment to get the amount to substract
//   from absolute virtual addresses to the virtual addresses in the
//   ELF file.
//
//   Note: Matching a memory mapping to the LOAD segment(s) in it is hard!
//   You can have instances where multiple memory mappings contain a
//   single LOAD segment (e.g. huge_pages):
//   3fc00000-41600000 r-xp 3d000000 00:1d 257 admarket.adfinder/adfinder
//   41600000-46a95000 r-xp 3ea00000 00:1d 257 admarket.adfinder/adfinder
//   ELF Program Header:
//   Type           Offset             VirtAddr           PhysAddr
//               FileSiz            MemSiz              Flags  Align
//   LOAD           0x000000003d000000 0x000000003fc00000 0x000000003fc00000
//               0x0000000006e94a14 0x0000000006e94a14  R E    0x200000
//
//   There can also be one mapping for several LOAD segments e.g.
//   7f621c2f6000-7f621c51b000 r-xp 00000000 00:1b 129076798 libstdc++.so.6.0.29
//   ELF Program Header:
//   Type           Offset             VirtAddr           PhysAddr
//               FileSiz            MemSiz              Flags  Align
//   LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000
//               0x00000000000985f8 0x00000000000985f8  R      0x1000
//   LOAD           0x0000000000099000 0x0000000000099000 0x0000000000099000
//                0x0000000000129759 0x0000000000129759  R E    0x1000
//   LOAD           0x00000000001c3000 0x00000000001c3000 0x00000000001c3000
//                0x000000000006125d 0x000000000006125d  R      0x1000
//
//   There can be memory mappings with NO load segments e.g.
//   7f621cd6d000-7f621cd6e000 ---p 002e2000 00:1b 129103448 libpython3.8.so.1.0
//
//   This is why we're just taking the first non-shared and readable mapping
//   and matching it against the first LOAD segment instead of attempting to
//   find the matching LOAD segment for each memory mapping.
//
//   Note2: Memory Mappings backed by a file marked as (deleted) still resolve
//   to the correct, original file when opening this file via the map_files path
//   (e.g. proc/<pid>/map_files/xxx-yyy); you will be reading the inode that
//   was actually mapped into the process.
bool ProcPidInfo::iterateAllMemoryMappings(
    MemoryMappingWithBaseLoadAddressCallback callback) const {
  std::string mappingName;
  std::optional<uintptr_t> elfBaseLoadAddress;
  std::shared_ptr<strobelight::ElfFile> elf;
  std::map<std::string, std::optional<uintptr_t>> elfBaseLoadAddressMap;

  return iterateAllMemoryMappings([&](const MemoryMapping& mm) {
    if (mm.shared || !mm.readable) {
      return callback(mm, std::nullopt, nullptr);
    }

    if (mm.name.empty() || mm.name[0] != '/' ||
        (mm.name.compare(0, kAnonHugePage.size(), kAnonHugePage) == 0)) {
      return callback(mm, std::nullopt, nullptr);
    }

    // In the common case the mappings for a file are grouped together
    // in /proc/<pid>/maps so it is unlikely that we will thrash the ElfFile.
    //
    // For ease of use we want to ensure that if it's possible for an ElfFile
    // to be opened for a mapping then the callback will include it.
    if (mappingName == mm.name) {
      return callback(mm, elfBaseLoadAddress, elf);
    }

    mappingName = mm.name;
    elfBaseLoadAddress = std::nullopt;
    elf = std::make_shared<strobelight::ElfFile>();

    // /proc/<pid>/map_files/ paths are preferred for accessing ELF files of
    // mappings because they work correctly for deleted / modified files as well
    // as container based process files.
    //
    // According to the procfs man page
    // (https://man7.org/linux/man-pages/man5/procfs.5.html):
    //
    // "Capabilities are required to read the contents of the symbolic links in
    // this directory: before Linux 5.9, the reading process requires
    // CAP_SYS_ADMIN in the initial user namespace; since Linux 5.9, the reading
    // process must have either CAP_SYS_ADMIN or CAP_CHECKPOINT_RESTORE in the
    // user namespace where it resides."
    //
    // If the reading process doesn't have CAP_SYS_ADMIN we fall back to reading
    // from /proc/<pid>/root/<mapping name>.
    fs::path file;
    if (haveEffectiveSysAdminCapability()) {
      file = getProcfsPath("map_files") /
          fmt::format("{:x}-{:x}", mm.startAddr, mm.endAddr);
    } else {
      if (mm.name.find(kDeleted) != std::string::npos) {
        elf = nullptr;
        return callback(mm, std::nullopt, elf);
      }
      file = getProcfsRoot(mm.name);
    }

    auto elfFileRes = elf->open(file.c_str());
    if (!elfFileRes) {
      elf = nullptr;
      return callback(mm, elfBaseLoadAddress, elf);
    }

    if (elf->eType() == ET_EXEC) {
      // If this isn't relocatable e.g. not ET_REL or ET_DYN
      // then it should always be loaded at the default load address
      // even if there is some alignment padding in the memory mapping
      // so let's not mess around with address adjustment.
      elfBaseLoadAddress = 0;
    } else {
      // Only need to check the map for relocatable file mappings
      // that are not contiguous because the base load address
      // calculation works only for the first mapping entry.
      auto it = elfBaseLoadAddressMap.find(mm.name);
      if (it != elfBaseLoadAddressMap.end()) {
        // The memory mapped file is not contiguous in /proc/pid/maps
        return callback(mm, it->second, elf);
      }

      std::optional<GElf_Addr> lowestVaddr = std::nullopt;
      GElf_Off lowestOffset = 0;

      elf->iterateProgramHeaders([&](const GElf_Phdr& h) {
        if (h.p_type == PT_LOAD) {
          lowestVaddr = h.p_vaddr;
          lowestOffset = h.p_offset;
          return true;
        }
        return false;
      });

      if (!lowestVaddr) {
        strobelight_lib_print(
            STROBELIGHT_LIB_INFO,
            fmt::format(
                "Could not find an eligible virtual load address for {} @ {} - {} in process {} [{}]",
                mm.name,
                (void*)mm.startAddr,
                (void*)mm.endAddr,
                getName(),
                pid_)
                .c_str());
      } else {
        elfBaseLoadAddress =
            (mm.startAddr - mm.fileOffset) - (*lowestVaddr - lowestOffset);
      }
      elfBaseLoadAddressMap.emplace(mm.name, elfBaseLoadAddress);
    }
    return callback(mm, elfBaseLoadAddress, elf);
  });
}

ssize_t ProcPidInfo::readMemory(void* dest, const void* src, size_t len) const {
  struct iovec local[1];
  struct iovec remote[1];
  local[0].iov_base = dest;
  local[0].iov_len = len;
  remote[0].iov_base = (void*)src;
  remote[0].iov_len = len;
  return ::process_vm_readv(pid_, local, 1, remote, 1, 0);
}

size_t ProcPidInfo::readCString(char* dest, const char* src, size_t maxLen)
    const {
  if (maxLen < 1) {
    return -EINVAL;
  }

  static const size_t kPageSize = ::sysconf(_SC_PAGESIZE);
  char* const destBase = dest;
  size_t destLen = maxLen - 1;
  size_t totalCstrLen = 0;
  while (destLen > 0) {
    // read up to a page at a time
    const size_t readSize =
        std::min<size_t>(destLen, kPageSize - ((uintptr_t)src % kPageSize));
    const auto bytesRead = readMemory((void*)dest, src, readSize);
    if (bytesRead < 0) {
      break;
    }

    const size_t cstrLen = strnlen(dest, bytesRead);
    totalCstrLen += cstrLen;
    if (cstrLen < static_cast<const unsigned int>(bytesRead)) {
      break;
    }

    dest += bytesRead;
    destLen -= bytesRead;
    src += bytesRead;
  }

  destBase[totalCstrLen] = '\0';
  return totalCstrLen;
}

// Returns vector of pids of all running processes
std::vector<pid_t> ProcPidInfo::getRunningPids(const std::string& rootDir) {
  std::vector<pid_t> result;
  auto path = getActualProcFsPath(rootDir);
  auto success = readPidListFromDirectory(path.string(), result);
  if (!success) {
    throw std::runtime_error("Unable to read /proc");
  }
  return result;
}

bool ProcPidInfo::pidExists(pid_t pid, const std::string& rootDir) {
  std::error_code ec{};
  auto path = getActualProcFsPath(rootDir) / std::to_string(pid);
  return std::filesystem::exists(path, ec);
}

void ProcPidInfo::readProcExe() {
  auto fn = getProcfsPath("exe");
  // For non-kernel processes, /proc/PID/exe is a symlink.  Since we're only
  // reading this when !isKernelProcess(), this is sufficient to read out the
  // path.  fileExists() cannot be used because then we can't mock out the
  // linked-to path.
  std::error_code ec{};
  if (!std::filesystem::is_symlink(fn, ec)) {
    strobelight_lib_print(
        STROBELIGHT_LIB_DEBUG,
        fmt::format("/proc/[pid]/exe doesn't exist for process {}", pid_)
            .c_str());
    return;
  }
  std::string temp;
  if (readProcfsSymlink(fn, &temp)) {
    exe_ = temp;
  }
}

bool ProcPidInfo::readProcStat() {
  auto path = getProcfsPath("stat");
  std::string raw;
  if (!readProcfsFileToString(path, &raw)) {
    return false;
  }

  // Process name can contain spaces and can be in brackets, for example
  // "2200782 ((sd-pam)) S ..." So we need to find the last ')'
  auto commEnd = raw.rfind(')');
  if (commEnd == std::string::npos) {
    return false;
  }

  // Split the rest of raw into fields. Start with field_idx set to 2 since we
  // have already advanced by 2 fields.
  size_t start = 0;
  size_t field_idx = 2;
  static constexpr int kExpectedNumFields = 52;
  static constexpr std::string_view delim{" "};
  auto fields = std::string_view(raw).substr(commEnd + 2);
  while (start < fields.size()) {
    std::string_view value;
    nextToken(fields, delim, start, value);
    start += value.size() + 1;

    // skip blanks.
    if (value.empty()) {
      continue;
    }

    // increment field_idx to represent the field we are currently evaluating.
    ++field_idx;

    // fixed fields
    if (field_idx == PROC_STAT_FIELD_STARTTIME) {
      static const long kClockTicks = ::sysconf(_SC_CLK_TCK);
      int64_t starttime;
      std::from_chars(value.data(), value.data() + value.size(), starttime);
      startTimeAfterBoot_ = std::chrono::seconds(starttime / kClockTicks);
    }

    // Variable fields
    if (field_idx == PROC_STAT_FIELD_UTIME) {
      std::from_chars(value.data(), value.data() + value.size(), stats_.utime);
    }

    if (field_idx == PROC_STAT_FIELD_STIME) {
      std::from_chars(value.data(), value.data() + value.size(), stats_.stime);
    }

    if (field_idx == PROC_STAT_FIELD_NUM_THREADS) {
      std::from_chars(
          value.data(), value.data() + value.size(), stats_.threadCount);
    }

    if (field_idx == PROC_STAT_FIELD_RSS) {
      static const long kPageSize = ::sysconf(_SC_PAGESIZE);
      std::from_chars(
          value.data(), value.data() + value.size(), stats_.rssBytes);
      stats_.rssBytes *= kPageSize;
    }
  }
  if (field_idx != kExpectedNumFields) {
    return false;
  }

  return true;
}

bool ProcPidInfo::readProcInfo() {
  // The /proc/PID/status file consists of multiple lines, each start with
  // a string field name and then tab-separated values. Therefore we keep a
  // list of pair of field name prefix and parser callback of how to process
  // value for that field.
  using StatusFieldCallback = std::function<bool(std::string_view)>;
  auto fullStr = [](std::string& target, std::string_view line) -> bool {
    target = line;
    return true;
  };

  auto lastPid = [](pid_t& target, std::string_view line) -> bool {
    auto pidStr = getLast('\t', line);
    if (pidStr.empty()) {
      return false;
    }
    if (!trimWhitespace(pidStr)) {
      return false;
    }

    auto ec =
        std::from_chars(pidStr.data(), pidStr.data() + pidStr.size(), target)
            .ec;
    if (ec != std::errc{}) {
      return false;
    }
    return true;
  };
  auto secondUid = [](uid_t& target, std::string_view line) -> bool {
    static constexpr std::string_view delim{"\t"};
    static constexpr int kTargetFieldIdx = 1;
    static constexpr int kExpectedNumFields = 4;

    std::string_view targetField;
    size_t idx = 0;
    size_t start = 0;

    auto fields = std::string_view(line);
    while (start < fields.size()) {
      std::string_view field;
      nextToken(fields, delim, start, field);
      start += field.size() + 1;

      // skip blanks.
      if (field.empty()) {
        continue;
      }

      // fields are real, effective, saved set, and filesystem UIDs
      // we are retreiving effective UID
      if (idx == kTargetFieldIdx) {
        targetField = std::string_view(field);
      }
      ++idx;
    }

    if (idx != kExpectedNumFields) {
      return false;
    }

    if (std::from_chars(
            targetField.data(), targetField.data() + targetField.size(), target)
            .ec == std::errc{}) {
      return true;
    } else {
      return false;
    }
  };
  auto sigField = [](uint64_t& target, std::string_view line) -> bool {
    // These fields are hex encoded 64 bit ints
    auto strValue = getLast('\t', line);
    if (strValue.empty()) {
      return false;
    }
    std::istringstream converter(std::string{strValue});
    converter >> std::hex >> target;
    return true;
  };
  auto memField = [](uint64_t& target, std::string_view line) -> bool {
    auto value = getLast('\t', line);
    if (value.empty()) {
      return false;
    }
    if (!removeSuffix(value, "kB")) {
      return false;
    }

    if (!trimWhitespace(value)) {
      return false;
    }

    uint64_t targetValue = 0;
    auto ec =
        std::from_chars(value.data(), value.data() + value.size(), targetValue)
            .ec;
    if (ec != std::errc{}) {
      return false;
    }
    target = 1024ULL * targetValue;
    return true;
  };

  using std::placeholders::_1;
  std::vector<std::pair<std::string_view, StatusFieldCallback>> cbs = {
      {kNamePrefix, std::bind(fullStr, std::ref(name_), _1)},
      {kStatePrefix, std::bind(fullStr, std::ref(state_), _1)},
      {kPPidPrefix, std::bind(lastPid, std::ref(ppid_), _1)},
      {kUidPrefix, std::bind(secondUid, std::ref(uid_), _1)},
      {kGidPrefix, std::bind(secondUid, std::ref(gid_), _1)},
      {kTgidPrefix, std::bind(lastPid, std::ref(tgid_), _1)},
  };

  std::vector<std::pair<std::string_view, StatusFieldCallback>> nsCbs = {
      {kNSPidPrefix, std::bind(lastPid, std::ref(nspid_), _1)},
      {kNSTgidPrefix, std::bind(lastPid, std::ref(nstgid_), _1)},
  };
  auto nsCbsSize = nsCbs.size();

  // We use a separate vector of callbacks for the memory related information
  // to preserve backwards compatibility. We found that several strobelight
  // symbolizer tests failed with this change.
  std::vector<std::pair<std::string_view, StatusFieldCallback>> memSigCbs = {
      {kVmSizePrefix, std::bind(memField, std::ref(vmsize_), _1)},
      {kVmHwmPrefix, std::bind(memField, std::ref(vmhwm_), _1)},
      {kVmRssPrefix, std::bind(memField, std::ref(vmrss_), _1)},
      {kRssAnonPrefix, std::bind(memField, std::ref(rssanon_), _1)},
      {kRssFilePrefix, std::bind(memField, std::ref(rssfile_), _1)},
      {kRssShmemPrefix, std::bind(memField, std::ref(rssshmem_), _1)},
      {kSigBlkPrefix, std::bind(sigField, std::ref(sigblk_), _1)},
      {kSigIgnPrefix, std::bind(sigField, std::ref(sigign_), _1)},
      {kSigCgtPrefix, std::bind(sigField, std::ref(sigcgt_), _1)},
  };

  auto path = getProcfsPath("status");
  std::fstream fs(path, std::ios_base::in);
  std::string line;
  while (std::getline(fs, line)) {
    std::string_view l(line);
    for (auto it = cbs.begin(); it != cbs.end(); it++) {
      if (removePrefix(l, it->first)) {
        if (!it->second(l)) {
          return false;
        }
        cbs.erase(it);
        break;
      }
    }

    for (auto it = memSigCbs.begin(); it != memSigCbs.end(); it++) {
      if (removePrefix(l, it->first)) {
        if (!it->second(l)) {
          strobelight_lib_print(
              STROBELIGHT_LIB_WARN,
              fmt::format("Unable to parse value for {}", it->first).c_str());
          continue;
        }
        memSigCbs.erase(it);
        break;
      }
    }

    // Break these out separate because kernels before 4.1 don't support NS keys
    for (auto it = nsCbs.begin(); it != nsCbs.end(); it++) {
      if (removePrefix(l, it->first)) {
        if (!it->second(l)) {
          return false;
        }
        nsCbs.erase(it);
        break;
      }
    }

    if (cbs.empty() && memSigCbs.empty()) {
      break;
    }
  }
  return cbs.empty() && nsCbs.size() <= nsCbsSize;
}

bool ProcPidInfo::readProcSmapsRollup() {
  auto memField = [](uint64_t& target, uint64_t value) {
    target = 1024ULL * value;
  };

  using StatusFieldCallback = std::function<void(uint64_t)>;
  std::vector<std::pair<std::string, StatusFieldCallback>> cbs = {
      {fmt::format("{} {}", kPssPrefix, kMemPattern),
       [&](uint64_t value) { return memField(pss_, value); }},
      {fmt::format("{} {}", kPssAnonPrefix, kMemPattern),
       [&](uint64_t value) { return memField(pssanon_, value); }},
      {fmt::format("{} {}", kPssFilePrefix, kMemPattern),
       [&](uint64_t value) { return memField(pssfile_, value); }},
      {fmt::format("{} {}", kPssShmemPrefix, kMemPattern),
       [&](uint64_t value) { return memField(pssshmem_, value); }},
      {fmt::format("{} {}", kSwapPssPrefix, kMemPattern),
       [&](uint64_t value) { return memField(swappss_, value); }},
      {fmt::format("{} {}", kAnonHugePagePrefix, kMemPattern),
       [&](uint64_t value) { return memField(anonhugepage_, value); }},
  };

  auto path = getProcfsPath("smaps_rollup");
  std::fstream fs(path, std::ios_base::in);
  std::string line;
  while (std::getline(fs, line)) {
    for (auto it = cbs.begin(); it != cbs.end(); it++) {
      uint64_t target = 0;
      if (std::sscanf(line.c_str(), it->first.c_str(), &target) == 1) {
        it->second(target);
        cbs.erase(it);
        break;
      }
    }
  }
  return cbs.empty();
}

static std::string resolveLink(const std::string& link) {
  std::string path;
  return readSymlink(link, &path) ? path : link;
}

bool ProcPidInfo::getTargetNamespace(std::string& target_namespace) const {
  auto currentNamespace = std::string("/proc/self/ns/mnt");
  target_namespace = getProcfsPath("ns/mnt");
  // check if mount namespaces are different
  return (getpid() != getPid()) &&
      (resolveLink(currentNamespace) != resolveLink(target_namespace));
}

bool ProcPidInfo::readPidListFromDirectory(
    const std::string& path,
    std::vector<pid_t>& result) {
  for (auto const& dirEntry : std::filesystem::directory_iterator{path}) {
    if (!dirEntry.is_directory()) {
      continue;
    }
    auto dir = dirEntry.path().filename().string();
    pid_t pid;
    auto ec = std::from_chars(dir.data(), dir.data() + dir.size(), pid).ec;
    if (ec == std::errc{}) {
      result.push_back(pid);
    }
  }
  return result.size() > 0;
}

} // namespace facebook::pid_info
