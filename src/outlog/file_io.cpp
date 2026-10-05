#include "outlog/file_io.h"

#include <cstring>

#include "outlog/posix_fs.h"

namespace lle::outlog::detail {

std::string errno_text(const char* what, const std::string& path, int err) {
  return std::string(what) + " '" + path + "': " + std::strerror(err);
}

std::expected<void, std::string> write_index(const std::string& idx_path, std::span<const std::uint64_t> entries) {
  PosixFs fs;
  return write_index(fs, idx_path, entries);
}

}  // namespace lle::outlog::detail
