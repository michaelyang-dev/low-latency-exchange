#pragma once
// Provenance and ledger helpers shared by the engine harnesses (enginediff,
// crossdiff): git sha, dirty flag, content hash of the certified trees, build
// type, host and date, as fuzz/ledger/runs.jsonl records them (same fields as
// lobdiff). Harness code, not deterministic engine code.
#include <unistd.h>

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

namespace lle::engine::harness {

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

// FNV-1a over (relative path, contents) of every file in the certified trees.
inline std::string tree_hash() {
  namespace fs = std::filesystem;
  const fs::path root = LLE_SOURCE_DIR;
  std::vector<std::string> files;
  for (const char* dir : {"src/engine", "src/lob", "src/common", "src/proto/ouch50", "src/proto/itch50"}) {
    std::error_code ec;
    for (fs::recursive_directory_iterator it(root / dir, ec), end; !ec && it != end; it.increment(ec))
      if (it->is_regular_file()) files.push_back(fs::relative(it->path(), root).generic_string());
  }
  std::sort(files.begin(), files.end());
  lle::Fnv1a64 h;
  for (const std::string& f : files) {
    h.str(f);
    h.u(std::uint8_t{0});
    std::ifstream in(root / f, std::ios::binary);
    const std::string body((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
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
};

inline Provenance provenance() {
  Provenance p;
  const std::string dir = LLE_SOURCE_DIR;
  p.sha = shell_line("git -C '" + dir + "' rev-parse HEAD 2>/dev/null");
  if (p.sha.empty()) p.sha = "unknown";
  p.dirty = !shell_line("git -C '" + dir +
                        "' status --porcelain --untracked-files=all -- src/engine src/lob src/common src/proto "
                        "fuzz/engine 2>/dev/null")
                 .empty();
  p.tree = tree_hash();
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

}  // namespace lle::engine::harness
