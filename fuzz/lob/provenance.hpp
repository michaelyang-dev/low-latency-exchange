#pragma once
// Provenance for differential-harness ledger records (04-order-book §8
// "Honest counting"): git SHA, dirty flag, a content hash of the certified
// source trees, build type, host and date. Shared by lobdiff and
// itch_replay_diff. Cold path only.
#include <sys/stat.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

#include "common/hash.h"

#ifndef LLE_SOURCE_DIR
#define LLE_SOURCE_DIR "."
#endif
#ifndef LLE_BUILD_TYPE
#define LLE_BUILD_TYPE "unknown"
#endif
#ifndef LLE_SANITIZE_STR
#define LLE_SANITIZE_STR ""
#endif

namespace lle::lobfuzz {

inline std::string shell_line(const std::string& cmd) {
  std::string out;
  if (FILE* p = ::popen(cmd.c_str(), "r")) {
    char buf[256];
    while (std::fgets(buf, sizeof buf, p) != nullptr) out += buf;
    ::pclose(p);
  }
  while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) out.pop_back();
  return out;
}

// Content hash of the trees the ledger certifies (04 §8 "Honest counting"):
// FNV-1a over (relative path, contents) of every file, sorted by path.
inline std::string tree_hash() {
  namespace fs = std::filesystem;
  const fs::path root = LLE_SOURCE_DIR;
  std::vector<std::string> files;
  for (const char* dir : {"src/lob", "src/book", "src/common"}) {
    std::error_code ec;
    for (fs::recursive_directory_iterator it(root / dir, ec), end; !ec && it != end; it.increment(ec)) {
      if (it->is_regular_file()) files.push_back(fs::relative(it->path(), root).generic_string());
    }
  }
  std::sort(files.begin(), files.end());
  lle::Fnv1a64 h;
  for (const std::string& f : files) {
    h.str(f);
    h.u(std::uint8_t{0});
    std::ifstream in(root / f, std::ios::binary);
    std::string body((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    h.str(body);
    h.u(std::uint8_t{0});
  }
  char buf[32];
  std::snprintf(buf, sizeof buf, "%016llx", static_cast<unsigned long long>(h.value()));
  return buf;
}

inline std::string json_escape(std::string_view s) {
  std::string o;
  for (char c : s) {
    if (c == '"' || c == '\\') {
      o += '\\';
      o += c;
    } else if (static_cast<unsigned char>(c) < 0x20) {
      o += ' ';
    } else {
      o += c;
    }
  }
  return o;
}

struct Provenance {
  std::string sha, tree, host, build, date;
  bool dirty = false;
  // False if a certified source file is newer than this executable: the tree
  // hash, computed from the sources at run time, would then not describe the
  // code that runs, so harnesses refuse to write ledger records.
  bool fresh = true;
  std::string stale_file;
};

inline std::string executable_path() {
#if defined(__APPLE__)
  char buf[4096];
  std::uint32_t n = sizeof buf;
  if (_NSGetExecutablePath(buf, &n) == 0) return buf;
  return {};
#else
  std::error_code ec;
  const auto p = std::filesystem::read_symlink("/proc/self/exe", ec);
  return ec ? std::string{} : p.string();
#endif
}

// Newest certified source (src/lob, src/book, src/common, fuzz/lob) compared
// with the executable's modification time.
inline bool binary_is_fresh(std::string* stale_file) {
  namespace fs = std::filesystem;
  struct stat exe{};
  const std::string self = executable_path();
  if (self.empty() || ::stat(self.c_str(), &exe) != 0) return true;  // cannot tell: do not block
  const fs::path root = LLE_SOURCE_DIR;
  for (const char* dir : {"src/lob", "src/book", "src/common", "fuzz/lob"}) {
    std::error_code ec;
    for (fs::recursive_directory_iterator it(root / dir, ec), end; !ec && it != end; it.increment(ec)) {
      struct stat st{};
      if (it->is_regular_file() && ::stat(it->path().c_str(), &st) == 0 && st.st_mtime > exe.st_mtime) {
        *stale_file = fs::relative(it->path(), root).generic_string();
        return false;
      }
    }
  }
  return true;
}

inline Provenance provenance() {
  Provenance p;
  const std::string dir = LLE_SOURCE_DIR;
  p.sha = shell_line("git -C '" + dir + "' rev-parse HEAD 2>/dev/null");
  if (p.sha.empty()) p.sha = "unknown";
  p.dirty = !shell_line("git -C '" + dir +
                        "' status --porcelain --untracked-files=all -- src/lob src/book src/common fuzz/lob 2>/dev/null")
                 .empty();
  p.tree = tree_hash();
  p.fresh = binary_is_fresh(&p.stale_file);
  char host[256] = {};
  ::gethostname(host, sizeof host - 1);
  p.host = host;
  p.build = LLE_BUILD_TYPE;
  if (std::string_view(LLE_SANITIZE_STR).size() != 0) p.build += std::string("+") + LLE_SANITIZE_STR;
  const std::time_t t = std::time(nullptr);
  char date[32];
  std::strftime(date, sizeof date, "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));
  p.date = date;
  return p;
}

}  // namespace lle::lobfuzz
