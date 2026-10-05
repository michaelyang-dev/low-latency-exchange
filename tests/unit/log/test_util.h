#pragma once
// Helpers shared by the nlog unit tests.
#include <unistd.h>

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

#include "log/memory_sink.h"

namespace lle::nlog::test {

inline std::string temp_path(std::string_view name) {
  const char* dir = std::getenv("TMPDIR");
  std::string p = (dir != nullptr && *dir != '\0') ? dir : "/tmp";
  if (p.back() != '/') p += '/';
  p += "nlog_test_" + std::to_string(::getpid()) + "_" + std::string(name) + ".nlog";
  return p;
}

inline std::vector<std::byte> read_file(const std::string& path) {
  std::vector<std::byte> out;
  std::FILE* f = std::fopen(path.c_str(), "rb");
  if (f == nullptr) return out;
  std::byte buf[65536];
  std::size_t n = 0;
  while ((n = std::fread(buf, 1, sizeof buf, f)) != 0) out.insert(out.end(), buf, buf + n);
  std::fclose(f);
  return out;
}

// Consumes and discards whatever earlier tests left in the rings (and frees the
// rings of threads that have exited), so each test starts from empty rings even
// when the whole binary runs in one process.
inline void drain_and_discard() {
  MemorySink s;
  if (s.attach()) s.drain();
}

}  // namespace lle::nlog::test
