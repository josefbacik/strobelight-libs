// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "strobelight/bpf_lib/util/ElfFile.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace facebook::strobelight {

ElfFile::ElfFile(ElfFile&& other) noexcept {
  std::swap(elfFile_, other.elfFile_);
  std::swap(fd_, other.fd_);
  std::swap(fileMMap_, other.fileMMap_);
  std::swap(fileMMapLength_, other.fileMMapLength_);
  std::swap(eType_, other.eType_);
  std::swap(initialized_, other.initialized_);
}

ElfFile& ElfFile::operator=(ElfFile&& other) noexcept {
  if (this != &other) {
    return *this;
  }
  std::swap(elfFile_, other.elfFile_);
  std::swap(fd_, other.fd_);
  std::swap(fileMMap_, other.fileMMap_);
  std::swap(fileMMapLength_, other.fileMMapLength_);
  std::swap(eType_, other.eType_);
  std::swap(initialized_, other.initialized_);
  return *this;
}

ElfFile::~ElfFile() {
  if (elfFile_) {
    elf_end(elfFile_);
  }
  if (fileMMap_) {
    munmap(fileMMap_, fileMMapLength_);
  }
  if (fd_ >= 0) {
    close(fd_);
  }
}

bool ElfFile::open(const std::string& path) {
  if (elf_version(EV_CURRENT) == EV_NONE) {
    return false;
  }

  fd_ = ::open(path.c_str(), O_RDONLY);
  if (fd_ < 0) {
    return false;
  }

  struct stat sb {};
  if (fstat(fd_, &sb) < 0) {
    return false;
  }

  fileMMapLength_ = sb.st_size;

  fileMMap_ = static_cast<char*>(
      mmap(nullptr, fileMMapLength_, PROT_READ, MAP_SHARED, fd_, 0));
  if (fileMMap_ == MAP_FAILED) {
    return false;
  }

  elfFile_ = elf_memory(fileMMap_, fileMMapLength_);
  if (!elfFile_) {
    return false;
  }

  if (elf_kind(elfFile_) != ELF_K_ELF) {
    return false;
  }

  GElf_Ehdr elfHeader;
  if (!gelf_getehdr(elfFile_, &elfHeader)) {
    return false;
  }
  eType_ = elfHeader.e_type;

  initialized_ = true;
  return true;
}

void ElfFile::iterateProgramHeaders(
    const std::function<bool(const GElf_Phdr&)>& func) const {
  size_t phdrCount = 0;
  if (!initialized_ || elf_getphdrnum(elfFile_, &phdrCount) < 0) {
    return;
  }

  GElf_Phdr pHdr;
  for (size_t idx = 0;
       idx < phdrCount && gelf_getphdr(elfFile_, idx, &pHdr) != nullptr;
       ++idx) {
    if (func(pHdr)) {
      return;
    }
  }
  return;
}

// Load a seciton header into provided GElf_Shdr by index
bool ElfFile::getSection(size_t index, GElf_Shdr& sectionHeader)
    const noexcept {
  if (!initialized_) {
    return false;
  }
  Elf_Scn* eScn = elf_getscn(elfFile_, index);
  return (gelf_getshdr(eScn, &sectionHeader) != nullptr);
}

// return the name of the section header located at provided index
std::string ElfFile::getSectionName(size_t index) const noexcept {
  GElf_Shdr sectionHeader;
  if (!initialized_ || !getSection(index, sectionHeader)) {
    return "";
  }

  size_t shdrstrndx;
  if (elf_getshdrstrndx(elfFile_, &shdrstrndx) != 0) {
    return "";
  }

  const char* const name =
      elf_strptr(elfFile_, shdrstrndx, sectionHeader.sh_name);
  if (name == nullptr) {
    return "";
  }
  return name;
}

std::unordered_map<std::string, std::optional<ElfFile::Symbol>>
ElfFile::getSymbolsByName(
    const std::unordered_set<std::string>& names) const noexcept {
  std::unordered_set<unsigned char> types{STT_OBJECT, STT_FUNC, STT_GNU_IFUNC};

  std::unordered_map<std::string, std::optional<ElfFile::Symbol>> result(
      names.size());
  if (names.empty() || !initialized_) {
    return result;
  }

  for (const std::string& name : names) {
    result[name] = std::nullopt;
  }

  Elf_Scn* eScn = nullptr;
  GElf_Shdr sectionHeader;
  GElf_Sym symbol;

  while ((eScn = elf_nextscn(elfFile_, eScn)) != nullptr) {
    if (!gelf_getshdr(eScn, &sectionHeader) ||
        (sectionHeader.sh_type != SHT_DYNSYM &&
         sectionHeader.sh_type != SHT_SYMTAB)) {
      continue;
    }

    Elf_Data* symtab_data = nullptr;
    while ((symtab_data = elf_getdata(eScn, symtab_data)) != nullptr) {
      unsigned i = 0;
      while (gelf_getsym(symtab_data, i++, &symbol)) {
        const char* name =
            elf_strptr(elfFile_, sectionHeader.sh_link, symbol.st_name);
        if (!types.contains(GELF_ST_TYPE(symbol.st_info)) || !name) {
          continue;
        }

        auto symbolItr = result.find(name);
        if (symbolItr == result.end() || symbolItr->second != std::nullopt) {
          continue;
        }

        result[name] = {elf_ndxscn(eScn), sectionHeader, symbol, name};
      }
    }
  }
  return result;
}

GElf_Sxword ElfFile::getRelocationAdjustment(
    const ElfFile::Symbol& symbol) const {
  // look for addend relocation against sym.st_value
  Elf_Scn* eScn = nullptr;
  GElf_Shdr sectionHeader;

  while ((eScn = elf_nextscn(elfFile_, eScn)) != nullptr) {
    Elf_Data* data = elf_getdata(eScn, nullptr);
    if (!data || !gelf_getshdr(eScn, &sectionHeader) ||
        sectionHeader.sh_type != SHT_RELA) {
      continue;
    }

    size_t entries =
        (sectionHeader.sh_entsize == 0
             ? 0
             : sectionHeader.sh_size / sectionHeader.sh_entsize);

    for (int idx = 0; (size_t)idx < entries; ++idx) {
      GElf_Rela rela;
      if (!gelf_getrela(data, idx, &rela)) {
        continue;
      }
      if (rela.r_offset != symbol.sym.st_value) {
        continue;
      }
      if (GELF_R_TYPE(rela.r_info) == R_X86_64_RELATIVE) {
        return rela.r_addend;
      }
    }
  }
  return 0;
}

bool ElfFile::getSectionContainingAddress(
    GElf_Addr addr,
    GElf_Shdr& sectionHeader) const noexcept {
  Elf_Scn* eScn = nullptr;

  while ((eScn = elf_nextscn(elfFile_, eScn)) != nullptr) {
    if (!gelf_getshdr(eScn, &sectionHeader)) {
      continue;
    }
    if ((addr >= sectionHeader.sh_addr) &&
        (addr < (sectionHeader.sh_addr + sectionHeader.sh_size))) {
      return true;
    }
  }
  return false;
}

} // namespace facebook::strobelight
